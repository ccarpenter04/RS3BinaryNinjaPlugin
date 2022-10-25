from typing import Optional

from binaryninja import Type, BinaryView


class JagTypes:
    current_time_ms_name = 'jag::FrameTime::m_CurrentMS'

    client_name = 'jag::Client'
    client: Optional[Type] = None

    isaac_name = 'jag::Isaac'
    isaac: Optional[Type] = None

    heap_interface_name = 'jag::HeapInterface'
    heap_interface: Optional[Type] = None

    conn_mgr_name = 'jag::ConnectionManager'
    conn_mgr: Optional[Type] = None

    client_prot_name = 'jag::ClientProt'
    client_prot: Optional[Type] = None

    server_prot_name = 'jag::ServerProt'
    server_prot: Optional[Type] = None

    packet_handler_name = 'jag::PacketHandler'
    packet_handler: Optional[Type] = None

    packet_name = 'jag::Packet'
    packet: Optional[Type] = None

    coord_grid_name = 'jag::game::CoordGrid'
    coord_grid: Optional[Type] = None

    vector2_name = 'jag::math::Vector2'
    vector2: Optional[Type] = None

    vector3_name = 'jag::math::Vector3'
    vector3: Optional[Type] = None

    frustrum_name = 'jag::math::Frustrum'
    frustrum: Optional[Type] = None

    hitmark_name = 'jag::Hitmark'
    hitmark: Optional[Type] = None

    player_game_state_name = 'jag::game::PlayerGameState'
    player_game_state: Optional[Type] = None

    player_stat_name = 'jag::game::PlayerStat'
    player_stat: Optional[Type] = None

    # PlayerSkill may not actually be a type that Jagex has internally,
    # however it does correspond with the memory structure they're utilizing
    player_skill_name = 'jag::game::PlayerSkill'
    player_skill: Optional[Type] = None

    player_skill_xp_table_name = 'jag::game::PlayerSkillXPTable'
    player_skill_xp_table: Optional[Type] = None

    logged_in_player_name = "jag::LoggedInPlayer"
    logged_in_player: Optional[Type] = None

    console_name = "jag::game::Console"
    console: Optional[Type] = None

    minimenu_name = "jag::MiniMenu"
    minimenu: Optional[Type] = None

    obj_type_name = "jag::game::ObjType"
    obj_type: Optional[Type] = None

    world_name = "jag::game::World"
    world: Optional[Type] = None

    def create_types(self, bv: BinaryView):
        t_isaac = Type.structure(members=[
            (Type.int(4, False), 'valuesRemaining'),  # This may actually be values used, investigate.
            (Type.array(Type.int(4, False), 256), 'results'),
            (Type.array(Type.int(4, False), 256), 'mm'),
            # One of these is the counter, another is the accumulator
            (Type.int(4), 'aa'),
            (Type.int(4), 'bb'),
            (Type.int(4), 'cc')
        ], packed=True)
        bv.define_user_type(self.isaac_name, t_isaac)
        self.isaac = bv.get_type_by_name(self.isaac_name)

        t_coord_grid = Type.structure(members=[
            (Type.int(4, True), 'plane'),
            (Type.int(4, True), 'x'),
            (Type.int(4, True), 'y')
        ], packed=True)
        bv.define_user_type(self.coord_grid_name, t_coord_grid)
        self.coord_grid = bv.get_type_by_name(self.coord_grid_name)

        t_vector2 = Type.structure(members=[
            (Type.float(4), 'x'),
            (Type.float(4), 'y')
        ], packed=True)
        bv.define_user_type(self.vector2_name, t_vector2)
        self.vector2 = bv.get_type_by_name(self.vector2_name)

        t_vector3 = Type.structure(members=[
            (Type.float(4), 'x'),
            (Type.float(4), 'y'),
            (Type.float(4), 'z')
        ], packed=True)
        bv.define_user_type(self.vector3_name, t_vector3)
        self.vector3 = bv.get_type_by_name(self.vector3_name)

        t_frustrum = Type.structure(members=[
            (Type.array(Type.float(4), 72), 'values')
        ], packed=True)
        bv.define_user_type(self.frustrum_name, t_frustrum)
        self.frustrum = bv.get_type_by_name(self.frustrum_name)

        t_hitmark = Type.structure(members=[
            (Type.int(4), 'type'),
            (Type.int(4), 'damage'),
            (Type.int(4), 'cycle'),
            (Type.int(4), 'unknown1'),
            (Type.int(4), 'unknown2'),
            (Type.int(4), 'unknown3')
        ], packed=True)
        bv.define_user_type(self.hitmark_name, t_hitmark)
        self.hitmark = bv.get_type_by_name(self.hitmark_name)

        t_player_skill_xp_table = Type.structure(members=[
            (Type.int(8), 'unknown_1'),
            # This is usually either 99 or 120
            (Type.int(8), 'levels_available'),
            # The middle argument is invalid, not sure what it should be,
        ], packed=True)
        bv.define_user_type(self.player_skill_xp_table_name, t_player_skill_xp_table)
        self.player_skill_xp_table = bv.get_type_by_name(self.player_skill_xp_table_name)

        t_player_skill = Type.structure(members=[
            (Type.int(4), 'index'),
            (Type.int(4), 'max_level'),
            (Type.bool(), 'members'),
            (Type.bool(), 'unknown_1'),
            (Type.int(4), 'f2p_experience_cap'),
            (Type.int(4), 'f2p_level_cap'),
            (Type.int(4), 'unknown_2'),
            (Type.pointer(bv.arch, bv.get_type_by_name(self.player_skill_xp_table_name)), 'experience_table'),
            (Type.bool(), 'is_normal_skill'),  # This is false if it's an elite skill
        ], packed=True)
        bv.define_user_type(self.player_skill_name, t_player_skill)
        self.player_skill = bv.get_type_by_name(self.player_skill_name)

        t_player_stat = Type.structure(members=[
            (Type.pointer(bv.arch, bv.get_type_by_name(self.player_skill_name)), 'skill'),
            (Type.int(4), 'unknown1'),
            (Type.int(4), 'experience'),
            (Type.int(4), 'base_level'),
            (Type.int(4), 'current_level')
        ], packed=True)
        bv.define_user_type(self.player_stat_name, t_player_stat)
        self.player_stat = bv.get_type_by_name(self.player_stat_name)

        t_player_game_state = Type.structure(members=[
            (Type.pointer(bv.arch, Type.void()), 'unknown_ptr_to_a_string'),
            (Type.int(8), 'stat_quantity'),
            (Type.pointer(bv.arch, bv.get_type_by_name(self.player_stat_name)), 'stats')
        ], packed=True)
        bv.define_user_type(self.player_game_state_name, t_player_game_state)
        self.player_game_state = bv.get_type_by_name(self.player_game_state_name)

        t_heap_interface = Type.structure(packed=True)
        bv.define_user_type(self.heap_interface_name, t_heap_interface)
        self.heap_interface = bv.get_type_by_name(self.heap_interface_name)

        t_client_prot = Type.structure(members=[
            (Type.int(4, False), 'opcode'),
            (Type.int(4), 'size')
        ], packed=True)
        bv.define_user_type(self.client_prot_name, t_client_prot)
        self.client_prot = bv.get_type_by_name(self.client_prot_name)

        t_server_prot = Type.structure(members=[
            (Type.int(4, False), 'opcode'),
            (Type.int(4), 'size')
        ], packed=True)
        bv.define_user_type(self.server_prot_name, t_server_prot)
        self.server_prot = bv.get_type_by_name(self.server_prot_name)

        t_packethandler_builder = Type.structure(members=[
            (Type.pointer(bv.arch, Type.void()), 'vtable')
        ], packed=True).mutable_copy()
        t_packethandler_builder.width = 0x48
        bv.define_user_type(self.packet_handler_name, t_packethandler_builder.immutable_copy())
        self.packet_handler = bv.get_type_by_name(self.packet_handler_name)

        t_packet = Type.structure(members=[
            (Type.int(8), 'unk1'),
            (Type.int(8), 'capacity'),
            (Type.pointer(bv.arch, Type.int(1, False)), 'buffer'),
            (Type.int(8), 'offset'),
            (Type.int(4), 'unk2'),
            (Type.int(8), 'unk3')
        ], packed=True)
        bv.define_user_type(self.packet_name, t_packet)
        self.packet = bv.get_type_by_name(self.packet_name)

        t_logged_in_player = Type.structure(members=[
            (Type.pointer(bv.arch, bv.get_type_by_name(self.client_name)), 'client'),
            (Type.array(Type.int(1), 32), 'unknown_1'),
            (Type.bool()),
            (Type.array(Type.int(1), 28), 'unknown_2'),
            (Type.int(4), "player_node_index"),
            (Type.array(Type.int(1), 28), 'unknown_3'),
            # eastl::string display_name == how many bytes do they occupy?
            (Type.array(Type.int(1), 112), 'unknown_4')
        ], packed=True)
        bv.define_user_type(self.logged_in_player_name, t_logged_in_player)
        self.logged_in_player = bv.get_type_by_name(self.logged_in_player_name)

        t_console = Type.structure(members=[
            # TODO
        ], packed=True)
        bv.define_user_type(self.console_name, t_console)
        self.console = bv.get_type_by_name(self.console_name)

        t_minimenu = Type.structure(members=[
            # TODO
        ], packed=True)
        bv.define_user_type(self.minimenu_name, t_minimenu)
        self.minimenu = bv.get_type_by_name(self.minimenu_name)

        t_world = Type.structure(members=[
            # TODO
        ], packed=True)
        bv.define_user_type(self.world_name, t_world)
        self.world = bv.get_type_by_name(self.world_name)

        t_obj_type = Type.structure(members=[
            # TODO
        ], packed=True, ).mutable_copy()
        t_obj_type.width = 0x33c
        bv.define_user_type(self.obj_type_name, t_obj_type.immutable_copy())
        self.obj_type = bv.get_type_by_name(self.obj_type_name)
