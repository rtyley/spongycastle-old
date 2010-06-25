package org.bouncycastle.asn1.icao;

import org.bouncycastle.asn1.DERObjectIdentifier;

public interface ICAOObjectIdentifiers
{
    //
    // base id
    //
    static final String                 id_icao                   = "2.23.136";

    static final DERObjectIdentifier    id_icao_mrtd              = new DERObjectIdentifier(id_icao+".1");
    static final DERObjectIdentifier    id_icao_mrtd_security     = new DERObjectIdentifier(id_icao_mrtd+".1");

    // LDS security object, see ICAO Doc 9303-Volume 2-Section IV-A3.2
    static final DERObjectIdentifier    id_icao_ldsSecurityObject = new DERObjectIdentifier(id_icao_mrtd_security+".1");

    // CSCA master list, see TR CSCA Countersigning and Master List issuance
    static final DERObjectIdentifier    id_icao_cscaMasterList    = new DERObjectIdentifier(id_icao_mrtd_security+".2");
    static final DERObjectIdentifier    id_icao_cscaMasterListSigningKey = new DERObjectIdentifier(id_icao_mrtd_security+".3");

    // document type list, see draft TR LDS and PKI Maintenance, par. 3.2.1
    static final DERObjectIdentifier    id_icao_documentTypeList  = new DERObjectIdentifier(id_icao_mrtd_security+".4");

    // Active Authentication protocol, see draft TR LDS and PKI Maintenance,
    // par. 5.2.2
    static final DERObjectIdentifier    id_icao_aaProtocolObject  = new DERObjectIdentifier(id_icao_mrtd_security+".5");

    // CSCA name change and key reoll-over, see draft TR LDS and PKI
    // Maintenance, par. 3.2.1
    static final DERObjectIdentifier    id_icao_extensions        = new DERObjectIdentifier(id_icao_mrtd_security+".6");
    static final DERObjectIdentifier    id_icao_extensions_namechangekeyrollover = new DERObjectIdentifier(id_icao_extensions+".1");
}
