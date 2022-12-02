from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class Client:
    found_data: NxtAnalysisData
    set_main_state_function: Function
    main_init_function: Function

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_main_init(bv):
            Logger.log_warn("Failed to locate jag::Client::MainInit(jag::SystemInitParams const&)")
        if not self.find_checked_alloc_and_client_instance(bv):
            Logger.log_warn("Failed to locate jag::HeapInterface::GlobalAlloc and/or define client")
        if not self.find_set_main_state(bv):
            Logger.log_warn("Failed to locate jag::Client::SetMainState(MainState)")

        return True

    def find_set_main_state(self, bv: BinaryView) -> bool:
        located_func = None
        located_function_size = 250  # It should always be around ~25
        for func in bv.functions:
            if not ensure_func_analyzed(func):
                continue
            ref_count = len(list(bv.get_code_refs(func.start)))
            if ref_count == 24:
                unresolved_call_count = 0
                total_call_count = 0
                instructions = func.llil.instructions
                for insn in instructions:
                    if not isinstance(insn, LowLevelILCall):
                        continue
                    call_insn: LowLevelILCall = insn
                    called = get_called_func(bv, call_insn)
                    if called is None:
                        unresolved_call_count += 1
                    total_call_count += 1
                if unresolved_call_count == 1 and total_call_count == 1:
                    instruction_count = len(list(instructions))
                    if instruction_count < located_function_size:
                        located_func = func
                        located_function_size = instruction_count
        if located_func is None:
            return False
        log_info("Found jag::Client::SetMainState @ {}".format(hex(located_func.start)))
        self.set_main_state_function = located_func
        change_func_name(located_func, 'jag::Client::SetMainState')
        change_var(located_func.parameter_vars[0], "this",
                   Type.pointer(bv.arch, self.found_data.types.client))
        change_var(located_func.parameter_vars[1], "state", self.found_data.types.main_state)
        return True

    def find_main_init(self, bv: BinaryView) -> bool:
        """
        Looks for references to the SetErrorMode function in Kernel32.dll.
        There should only be one function that calls SetErrorMode and that is jag::Client::MainInit.
        Returns whether it successfully isolated that call
        """
        set_error_modes = bv.get_symbols_by_name('SetErrorMode')
        if len(set_error_modes) == 0:
            log_warn("Couldn't find the symbol Kernel32::SetErrorMode")
            return False
        set_error_mode_addr = set_error_modes[-1].address
        xrefs = list(bv.get_code_refs(set_error_mode_addr))
        if len(xrefs) != 1:
            log_warn('SetErrorMode is referenced {} times'.format(len(xrefs)))
            return False
        target_func = xrefs[0].function
        log_info('Found jag::Client::MainInit @ {:#x}'.format(target_func.start))
        self.main_init_function = target_func
        change_func_name(target_func, 'jag::Client::MainInit')
        change_var(target_func.parameter_vars[0], "this", Type.pointer(bv.arch, self.found_data.types.client))
        return True

    def find_checked_alloc_and_client_instance(self, bv: BinaryView) -> bool:
        if not self.find_alloc_and_client_ctor(bv):
            return False
        if self.find_static_client_instance(bv):
            logmsg: str
            if len(self.found_data.static_client_ptrs) == 1:
                logmsg = 'Found jag::Client* g_pApp @ {:#x}'.format(self.found_data.static_client_ptrs[0])
                bv.define_data_var(self.found_data.static_client_ptrs[0],
                                   Type.pointer(bv.arch, self.found_data.types.client),
                                   'g_pApp')
            else:
                logmsg = 'Found multiple jag::Client*'
                for idx, ptr in enumerate(self.found_data.static_client_ptrs):
                    logmsg += '\n    @ {:#x}'.format(ptr)
                    name = 'g_pApp'
                    if idx > 0:
                        name += str(idx)

                    bv.define_data_var(self.found_data.static_client_ptrs[idx],
                                       Type.pointer(bv.arch, self.found_data.types.client),
                                       name)

            log_info(logmsg)

        return True

    def find_alloc_and_client_ctor(self, bv: BinaryView) -> bool:
        """
        Searches through jag::App::MainInit until encountering a call to a function that has a very large number of refs
        that function will be jag::HeapInterface::CheckedAlloc

        The first call (as of 922-4) to CheckedAlloc will be allocating a large block of memory. This is the jag::Client
        The next call after CheckedAlloc will be to the jag::Client::ctor
        @param bv:
        @param main_init:
        @return:
        """
        ref_threshold = 1500
        found_alloc = False
        client_struct_size = 0
        client_struct_alignment = 0
        for llil in self.main_init_function.llil.instructions:
            (is_valid, dest_addr) = is_valid_function_call(bv, llil)
            if not is_valid or dest_addr is None:
                continue

            if not found_alloc:
                refs = list(bv.get_code_refs(dest_addr))
                if len(refs) < ref_threshold:
                    continue

                client_struct_size = llil.get_reg_value(RCX).value  # num_bytes
                client_struct_alignment = llil.get_reg_value(RDX).value  # alignment
                #                      0x633d0    size in version 921-4
                client_expected_size = 0x633e0  # size as of jag::Client version 922-4
                if client_struct_size != client_expected_size:
                    size_diff = abs(client_struct_size - client_expected_size)
                    if size_diff < 0x10:
                        log_warn('Client structure size deviates more than 16 bytes from expected.'
                                 'got {:#x} but expected within 16 bytes of {:#x}'
                                 .format(client_struct_size, client_expected_size))
                found_alloc = True
                checked_alloc = bv.get_function_at(dest_addr)
                self.found_data.checked_alloc_addr = checked_alloc.start
                change_func_name(checked_alloc, '{}::GlobalAlloc'.format(self.found_data.types.heap_interface_name))
                change_ret_type(checked_alloc, Type.pointer(bv.arch, Type.void()))
                change_var(checked_alloc.parameter_vars[0], 'num_bytes', Type.int(4))
                change_var(checked_alloc.parameter_vars[1], 'alignment', Type.int(4))
                for call_insn_llil in checked_alloc.llil.instructions:
                    if isinstance(call_insn_llil, LowLevelILCall):
                        alloc = get_called_func(bv, call_insn_llil)
                        if alloc is not None and len(list(alloc.parameter_vars)) == 3:
                            change_func_name(alloc, '{}::Alloc'.format(self.found_data.types.heap_interface_name))
                            change_ret_type(alloc, Type.pointer(bv.arch, Type.void()))
                            change_var(alloc.parameter_vars[0], 'this', Type.pointer(bv.arch, self.found_data.types.heap_interface))
                            change_var(alloc.parameter_vars[1], 'num_bytes', Type.int(4))
                            change_var(alloc.parameter_vars[2], 'alignment', Type.int(4))
            else:
                with StructureBuilder.builder(bv, QualifiedName(self.found_data.types.client_name)) as client_builder:
                    client_builder.members = [
                        (Type.pointer(bv.arch, Type.void()), 'vtable')
                    ]
                    client_builder.packed = True
                    client_builder.alignment = client_struct_alignment
                    client_builder.width = client_struct_size

                self.found_data.types.client = bv.get_type_by_name(self.found_data.types.client_name)
                client_ctor = bv.get_function_at(dest_addr)
                self.found_data.client_ctor_addr = client_ctor.start
                change_func_name(client_ctor, '{}::Client'.format(self.found_data.types.client_name))
                change_ret_type(client_ctor, Type.pointer(bv.arch, self.found_data.types.client))
                change_var(client_ctor.parameter_vars[0], 'this',
                           Type.pointer(bv.arch, self.found_data.types.client))
                break

        if self.found_data.client_ctor_addr is not None:
            # Search through the HLIL instructions of jag::Client::ctor looking for the vtable assignment
            client_ctor = bv.get_function_at(self.found_data.client_ctor_addr)
            vtable_assign_insn: Optional[HighLevelILAssign] = None
            for idx, insn in enumerate(list(client_ctor.hlil.instructions)):
                if idx >= 5:
                    log_error('Failed to locate vtable of jag::Client')
                    break

                if isinstance(insn, HighLevelILAssign):
                    ass_insn: HighLevelILAssign = insn
                    dest = ass_insn.dest
                    if isinstance(dest, HighLevelILDerefField):
                        field_insn: HighLevelILDerefField = dest
                        if isinstance(field_insn.src, HighLevelILVar):
                            n: HighLevelILVar = field_insn.src
                            if len(n.vars) > 0 and n.vars[0] == client_ctor.parameter_vars[0]:
                                if field_insn.offset == 0:
                                    vtable_assign_insn = ass_insn
                elif vtable_assign_insn is not None:
                    if isinstance(vtable_assign_insn.src.value, Undetermined):
                        log_debug('Value of jag::Client::vtable is Undetermined')
                        return False
                    else:
                        vtable_addr = vtable_assign_insn.src.value.value
                        bv.get_data_var_at(vtable_addr).name = "jag::Client::vtable"
                        log_info('Found jag::Client::vtable @ {:#x}'.format(vtable_addr))
                    break

        return found_alloc and self.found_data.types.client is not None

    def find_static_client_instance(self, bv: BinaryView) -> bool:
        """
        Searches jag::App::MainInit for where the jag::Client address is stored and sets the type
        and label of the data location appropriately
        @param bv: @return: True if found; False otherwise
        """
        ctor_refs = list(bv.get_code_refs(self.found_data.client_ctor_addr))
        if len(ctor_refs) != 1:
            log_error('Expected 1 xref to jag::Client::Client() but found {}'.format(len(ctor_refs)))
            return False

        call_site_addr = ctor_refs[0].address
        containing_funcs = bv.get_functions_containing(call_site_addr)
        if len(containing_funcs) != 1:
            log_error('Expected 1 func containing a call to jag::Client::Client() but found {}'.format(len(containing_funcs)))
            return False

        func = containing_funcs[0]
        call_insn = func.get_llil_at(call_site_addr)
        fun_insns = list(func.llil.instructions)
        start_idx = find_instruction_index(fun_insns, call_insn) + 1
        if start_idx <= 0:
            # shouldn't actually happen, but you never know
            log_error('Couldn\'t find call instruction in function it\'s supposed to be in')
            return False

        # the return value of jag::Client::ctor is the client address.
        # we need to track where the address stored in RAX goes
        # we expect to see the address get stored in 1 or more data locations within the next few instructions
        # we are going to track where the value of rax goes through the rest of the function. If we encounter an
        # instruction that we can't guarantee hasn't clobbered the register values, we clear the list of registers the
        # address is known to exist in.
        # While going through the instructions we will specifically look for stores with a destination of ConstPtr
        # by the time we reach the end of the function there should only be 1 data location that still
        # contains the address of the client
        current_addr_reg_locations: list[RegisterName] = ['rax']
        current_data_locations: list[int] = []
        for i in range(start_idx, len(fun_insns)):
            insn = fun_insns[i]
            if insn.operation == LowLevelILOperation.LLIL_CALL:
                # if we encounter a call then we can't guarantee the registers are preserved
                # without doing more introspection
                # TODO: Theoretically a call could change one of the known data locations
                #       I don't think there's a need to get that sophisticated yet
                current_addr_reg_locations.clear()
            elif insn.operation == LowLevelILOperation.LLIL_STORE:
                # Encountered a store. Look for a destination of ConstPtr and src of a known client addr register
                store_insn: LowLevelILStore = insn
                dest_insn: LowLevelILInstruction = store_insn.dest
                if isinstance(dest_insn, LowLevelILConstPtr):
                    dest_insn: LowLevelILConstPtr = dest_insn
                    dest_addr = dest_insn.constant
                    src_insn = store_insn.src
                    if isinstance(src_insn, LowLevelILReg):
                        reg_insn: LowLevelILReg = src_insn
                        if reg_insn.src.name in current_addr_reg_locations:
                            if dest_addr not in current_data_locations:
                                current_data_locations.append(dest_addr)
                        elif dest_addr in current_data_locations:
                            current_data_locations.remove(dest_addr)

            elif insn.operation == LowLevelILOperation.LLIL_SET_REG:
                set_insn: LowLevelILSetReg = insn

                dest_to_add = None
                src_reg = None
                src_insn = set_insn.src
                if isinstance(src_insn, LowLevelILReg):
                    reg_insn: LowLevelILReg = src_insn
                    src_reg = reg_insn.src.name
                    if str(src_reg) in current_addr_reg_locations:
                        dest_to_add = set_insn.dest.name

                if dest_to_add is not None:
                    # prevent something like mov rcx, rcx from messing with us
                    if src_reg != dest_to_add:
                        # check if the value of a known location is changing
                        if dest_to_add in current_addr_reg_locations:
                            current_addr_reg_locations.remove(dest_to_add)
                        else:
                            current_addr_reg_locations.append(dest_to_add)

        num_ptrs = len(current_data_locations)
        if num_ptrs == 0:
            log_error("Unable to locate jag::Client* s_pClient")
            return False
        elif num_ptrs > 1:
            # as of 922-4 there should only be 1 left over data location. warn if there are more
            log_warn('Found multiple static data locations for jag::Client* s_pClient. Is this correct?')

        self.found_data.static_client_ptrs = current_data_locations
        return True
