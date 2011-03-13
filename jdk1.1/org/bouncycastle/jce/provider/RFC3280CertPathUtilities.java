package org.spongycastle.jce.provider;

import org.spongycastle.asn1.x509.X509Extensions;

public class RFC3280CertPathUtilities
{
    protected static final String CERTIFICATE_POLICIES = X509Extensions.CertificatePolicies.getId();

    protected static final String POLICY_MAPPINGS = X509Extensions.PolicyMappings.getId();

    protected static final String INHIBIT_ANY_POLICY = X509Extensions.InhibitAnyPolicy.getId();

    protected static final String ISSUING_DISTRIBUTION_POINT = X509Extensions.IssuingDistributionPoint.getId();

    protected static final String FRESHEST_CRL = X509Extensions.FreshestCRL.getId();

    protected static final String DELTA_CRL_INDICATOR = X509Extensions.DeltaCRLIndicator.getId();

    protected static final String POLICY_CONSTRAINTS = X509Extensions.PolicyConstraints.getId();

    protected static final String BASIC_CONSTRAINTS = X509Extensions.BasicConstraints.getId();

    protected static final String CRL_DISTRIBUTION_POINTS = X509Extensions.CRLDistributionPoints.getId();

    protected static final String SUBJECT_ALTERNATIVE_NAME = X509Extensions.SubjectAlternativeName.getId();

    protected static final String NAME_CONSTRAINTS = X509Extensions.NameConstraints.getId();

    protected static final String AUTHORITY_KEY_IDENTIFIER = X509Extensions.AuthorityKeyIdentifier.getId();

    protected static final String KEY_USAGE = X509Extensions.KeyUsage.getId();

    protected static final String CRL_NUMBER = X509Extensions.CRLNumber.getId();

    protected static final String ANY_POLICY = "2.5.29.32.0";

    /*
     * key usage bits
     */
    protected static final int KEY_CERT_SIGN = 5;

    protected static final int CRL_SIGN = 6;

}
