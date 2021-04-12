#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:sta:si:sw=4:sts=4:et:
from itertools import zip_longest
from typing import Dict, List, Tuple
from .agent_based_api.v1 import exists, register, Result, Service, SNMPTree, State
from .agent_based_api.v1.type_defs import CheckResult, DiscoveryResult, StringTable


Section = Dict[str, List[Tuple[str, str]]]

def parse_snmp_entity(string_table: StringTable) -> Section:
    parsed = []
    for phy_class, phy_name, phy_model_name, phy_serial_num in string_table:
        if phy_class == '3' or phy_name == 'Chassis':
            parsed.append((phy_model_name, phy_serial_num))
    return { 'model_serial_pair': parsed }

def discover_snmp_entity(section: Section) -> DiscoveryResult:
    if section:
        yield Service(parameters = section)

def check_snmp_entity(params: Section, section: Section) -> CheckResult:
    for i, (valp, vals) in enumerate(zip_longest(
            params.get('model_serial_pair', []),
            section.get('model_serial_pair', []))):
        if i == 0:
            t = "ModelName, Serial: "
        else:
            t = ""
        if valp == vals:
            t += f"{valp}"
            s = State.OK
        else:
            t += f"{valp} != {vals}"
            s = State.CRIT
        yield Result(state = s, summary = t)


register.snmp_section(
    name = "snmp_entity",
    detect = exists(".1.3.6.1.2.1.47.1.1.1.1.11.*"),  # ENTITY-MIB::entPhysicalSerialNum
    fetch = SNMPTree(
        base = '.1.3.6.1.2.1.47.1.1.1.1',
        oids = [
	    '5',  # ENTITY-MIB::entPhysicalClass
	    '7',  # ENTITY-MIB::entPhysicalName
	    '13', # ENTITY-MIB::entPhysicalModelName
	    '11', # ENTITY-MIB::entPhysicalSerialNum
        ],
    ),
    parse_function = parse_snmp_entity,
)

register.check_plugin(
    name = "snmp_entity",
    service_name = "SNMP Entity",
    check_function = check_snmp_entity,
    check_default_parameters = {},
    discovery_function = discover_snmp_entity,
)
