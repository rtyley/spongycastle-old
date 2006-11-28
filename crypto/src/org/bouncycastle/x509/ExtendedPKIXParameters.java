package org.bouncycastle.x509;

import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.LDAPCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * This class extends the PKIXParameters with a validity model parameter.
 */
public class ExtendedPKIXParameters
    extends PKIXParameters
{

    private List stores;

    private Selector selector;

    private boolean additionalLocationsEnabled = false;

    private List additionalStores;

    /**
     * Creates an instance of <code>PKIXParameters</code> with the specified
     * <code>Set</code> of most-trusted CAs. Each element of the set is a
     * {@link TrustAnchor TrustAnchor}. <p/> Note that the <code>Set</code>
     * is copied to protect against subsequent modifications.
     *
     * @param trustAnchors a <code>Set</code> of <code>TrustAnchor</code>s
     * @throws InvalidAlgorithmParameterException
     *                              if the specified
     *                              <code>Set</code> is empty.
     * @throws NullPointerException if the specified <code>Set</code> is
     *                              <code>null</code>
     * @throws ClassCastException   if any of the elements in the <code>Set</code>
     *                              is not of type <code>java.security.cert.TrustAnchor</code>
     */
    public ExtendedPKIXParameters(Set trustAnchors)
        throws InvalidAlgorithmParameterException
    {
        super(trustAnchors);
        stores = new ArrayList();
        additionalStores = new ArrayList();
    }

    /**
     * Returns an instance with the parameters of a given
     * <code>PKIXParameters</code> object.
     *
     * @param pkixParams The given <code>PKIXParameters</code>
     * @return an extended wrapper for the original object.
     */
    public static ExtendedPKIXParameters getInstance(PKIXParameters pkixParams)
    {
        ExtendedPKIXParameters params;
        try
        {
            params = new ExtendedPKIXParameters(pkixParams.getTrustAnchors());
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(e.getMessage());
        }
        params.setParams(pkixParams);
        return params;
    }

    /**
     * Method to support <code>clone()</code> under J2ME.
     * <code>super.clone()</code> does not exist and fields are not copied.
     *
     * @param params Parameters to set. If this are
     *               <code>ExtendedPKIXParameters</code> they are copied to.
     */
    protected void setParams(PKIXParameters params)
    {
        setDate(params.getDate());
        setCertPathCheckers(params.getCertPathCheckers());
        setCertStores(params.getCertStores());
        setAnyPolicyInhibited(params.isAnyPolicyInhibited());
        setExplicitPolicyRequired(params.isExplicitPolicyRequired());
        setPolicyMappingInhibited(params.isPolicyMappingInhibited());
        setRevocationEnabled(params.isRevocationEnabled());
        setInitialPolicies(params.getInitialPolicies());
        setPolicyQualifiersRejected(params.getPolicyQualifiersRejected());
        setSigProvider(params.getSigProvider());
        setTargetCertConstraints(params.getTargetCertConstraints());
        try
        {
            setTrustAnchors(params.getTrustAnchors());
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(e.getMessage());
        }
        if (params instanceof ExtendedPKIXParameters)
        {
            ExtendedPKIXParameters _params = (ExtendedPKIXParameters)params;
            validityModel = _params.validityModel;
            useDeltas = _params.useDeltas;
            additionalLocationsEnabled = _params.additionalLocationsEnabled;
            selector = _params.selector == null ? null
                : (Selector)_params.selector.clone();
            stores = new ArrayList(_params.stores);
        }
    }

    /**
     * This is the default PKIX validity model. Actually there are two variants
     * of this: The PKIX model and the modified PKIX model. The PKIX model
     * verifies that all involved certificates must have been valid at the
     * current time. The modified PKIX model verifies that all involved
     * certificates were valid at the signing time. Both are indirectly choosen
     * with the {@link PKIXParameters#setDate(java.util.Date)} method, so this
     * methods sets the Date when <em>all</em> certificates must have been
     * valid.
     */
    public static final int PKIX_VALIDITY_MODEL = 0;

    /**
     * This model uses the following validity model. Each certificate must have
     * been valid at the moment where is was used. That means teh end
     * certificate must have been valid at the time the signature was done. The
     * CA certificate which signed the end certificate must have been valid,
     * when the end certificate was signed. The CA (or Root CA) certificate must
     * have been valid, when the CA certificate was signed and so on. So the
     * {@link PKIXParameters#setDate(java.util.Date)} method sets the time, when
     * the <em>end certificate</em> must have been valid. <p/> It is used e.g.
     * in the German signature law.
     */
    public static final int CHAIN_VALIDITY_MODEL = 1;

    private int validityModel = PKIX_VALIDITY_MODEL;

    private boolean useDeltas = true;

    /**
     * Defaults to <code>true</code>.
     *
     * @return Returns if delta CRLs should be used.
     */
    public boolean isUseDeltasEnabled()
    {
        return useDeltas;
    }

    /**
     * Sets if delta CRLs shoudl be used for checking the revocation status.
     *
     * @param useDeltas <code>true</code> if delta CRLs shoudl be used.
     */
    public void setUseDeltasEnabled(boolean useDeltas)
    {
        this.useDeltas = useDeltas;
    }

    /**
     * @return Returns the validity model.
     * @see #CHAIN_VALIDITY_MODEL
     * @see #PKIX_VALIDITY_MODEL
     */
    public int getValidityModel()
    {
        return validityModel;
    }

    /**
     * Adds a Java CertStore to this extended PKIX parameters. If the store uses
     * initialisation parameters of type
     * <code>CollectionCertStoreParameters</code> or <code></code> the
     * corresponding Bouncy Castle {@link Store} type is created additionally to
     * it.
     */
    public void addCertStore(CertStore store)
    {
        super.addCertStore(store);
        if (store.getType().equals("Collection"))
        {

            if (store.getCertStoreParameters() instanceof CollectionCertStoreParameters)
            {
                Collection coll = ((CollectionCertStoreParameters)store
                    .getCertStoreParameters()).getCollection();
                X509CollectionStoreParameters params = new X509CollectionStoreParameters(
                    coll);
                try
                {
                    stores.add(X509Store.getInstance("CERTIFICATE/COLLECTION",
                        params, "BC"));
                    stores.add(X509Store.getInstance("CRL/COLLECTION", params,
                        "BC"));
                }
                catch (Exception e)
                {
                    // cannot happen
                    throw new RuntimeException(e.getMessage());
                }
            }
            if (store.getCertStoreParameters() instanceof LDAPCertStoreParameters)
            {
                int port = ((LDAPCertStoreParameters)store
                    .getCertStoreParameters()).getPort();
                String server = ((LDAPCertStoreParameters)store
                    .getCertStoreParameters()).getServerName();
                X509LDAPCertStoreParameters params = new X509LDAPCertStoreParameters.Builder(
                    "ldap://" + server + ":" + port, null).build();
                try
                {
                    stores.add(X509Store.getInstance("CERTIFICATE/LDAP",
                        params, "BC"));
                    stores.add(X509Store.getInstance("CRL/LDAP", params, "BC"));
                }
                catch (Exception e)
                {
                    // cannot happen
                    throw new RuntimeException(e.getMessage());
                }
            }
        }
    }

    /**
     * Sets the Java CertStore to this extended PKIX parameters. If the stores
     * use initialisation parameters of type
     * <code>CollectionCertStoreParameters</code> or <code></code> the
     * corresponding Bouncy Castle {@link Store} types are created additionally
     * to it.
     */
    public void setCertStores(List stores)
    {
        super.setCertStores(stores);
        if (stores != null)
        {
            Iterator it = stores.iterator();
            while (it.hasNext())
            {
                addCertStore((CertStore)it.next());
            }
        }
    }

    /**
     * Sets to Bouncy Castle Stores for finding CRLs, certificates, attribute
     * certificates or cross certificates.
     * <p/>
     * The <code>List</code> is cloned.
     *
     * @param stores A list of stores to use.
     * @see #getStores
     */
    public void setStores(List stores)
    {
        if (stores == null)
        {
            this.stores = new ArrayList();
        }
        else
        {
            for (Iterator i = stores.iterator(); i.hasNext();)
            {
                if (!(i.next() instanceof Store))
                {
                    throw new ClassCastException(
                        "All elements of list must be "
                            + "of type org.bouncycastle.util.Store");
                }
            }
            this.stores = new ArrayList(stores);
        }
    }

    /**
     * Adds a Bouncy Castle {@link Store} to find CRLs, certificates, attribute
     * certificates or cross certificates.
     * <p/>
     * This method should be used to add local stores, like collection based
     * X.509 stores, if available. Local stores should be considered first,
     * before trying to use additional (remote) locations, because they do not
     * need possible additional network traffic.
     * <p/>
     * If <code>store</code> is <code>null</code> it is ignored.
     *
     * @param store The store to add.
     * @see #getStores
     */
    public void addStore(Store store)
    {
        if (stores != null)
        {
            stores.add(store);
        }
    }

    /**
     * Adds a additional Bouncy Castle {@link Store} to find CRLs, certificates, attribute
     * certificates or cross certificates.
     * <p/>
     * You should not use this method. This method is used for adding additional
     * X.509 stores, which are used to add (remote) locations, e.g. LDAP, found
     * during X.509 object processing, e.g. in certificates or CRLs. This method
     * is used in PKIX certification path processing.
     * <p/>
     * If <code>store</code> is <code>null</code> it is ignored.
     *
     * @param store The store to add.
     * @see #getStores()
     */
    public void addAddionalStore(Store store)
    {
        if (store != null)
        {
            additionalStores.add(store);
        }
    }

    /**
     * Returns an immutable <code>List</code> of additional Bouncy Castle
     * <code>Store</code>s used for finding CRLs, certificates, attribute
     * certificates or cross certificates.
     *
     * @return an immutable <code>List</code> of additional Bouncy Castle
     *         <code>Store</code>s. Never <code>null</code>.
     * @see #addAddionalStore(Store)
     */
    public List getAddionalStores()
    {
        return Collections.unmodifiableList(new ArrayList(additionalStores));
    }

    /**
     * Returns an immutable <code>List</code> of Bouncy Castle
     * <code>Store</code>s used for finding CRLs, certificates, attribute
     * certificates or cross certificates.
     *
     * @return an immutable <code>List</code> of Bouncy Castle
     *         <code>Store</code>s. Never <code>null</code>.
     * @see #setStores(List)
     */
    public List getStores()
    {
        return Collections.unmodifiableList(new ArrayList(stores));
    }

    /**
     * @param validityModel The validity model to set.
     * @see #CHAIN_VALIDITY_MODEL
     * @see #PKIX_VALIDITY_MODEL
     */
    public void setValidityModel(int validityModel)
    {
        this.validityModel = validityModel;
    }

    public Object clone()
    {
        ExtendedPKIXParameters params;
        try
        {
            params = new ExtendedPKIXParameters(getTrustAnchors());
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(e.getMessage());
        }
        params.setParams(this);
        return params;
    }

    /**
     * Returns if additional {@link X509Store}s for locations like LDAP found
     * in certificates or CRLs should be used.
     *
     * @return Returns <code>true</code> if additional stores are used.
     */
    public boolean isAdditionalLocationsEnabled()
    {
        return additionalLocationsEnabled;
    }

    /**
     * Sets if additional {@link X509Store}s for locations like LDAP found in
     * certificates or CRLs should be used.
     *
     * @param enabled <code>true</code> if additional stores are used.
     */
    public void setAdditionalLocationsEnabled(boolean enabled)
    {
        additionalLocationsEnabled = enabled;
    }

    /**
     * Returns the required constraints on the target certificate or attribute
     * certificate. The constraints are returned as an instance of
     * <code>Selector</code>. If <code>null</code>, no constraints are
     * defined.
     * <p/>
     * <p/>
     * The target certificate in a PKIX path may be a certificate or an
     * attribute certificate.
     * <p/>
     * Note that the <code>Selector</code> returned is cloned to protect
     * against subsequent modifications.
     *
     * @return a <code>Selector</code> specifying the constraints on the
     *         target certificate or attribute certificate (or <code>null</code>)
     * @see #setTargetConstraints
     * @see X509CertStoreSelector
     * @see X509AttributeCertStoreSelector
     */
    public Selector getTargetConstraints()
    {
        if (selector != null)
        {
            return (Selector)selector.clone();
        }
        else
        {
            return null;
        }
    }

    /**
     * Sets the required constraints on the target certificate or attribute
     * certificate. The constraints are specified as an instance of
     * <code>Selector</code>. If <code>null</code>, no constraints are
     * defined.
     * <p/>
     * The target certificate in a PKIX path may be a certificate or an
     * attribute certificate.
     * <p/>
     * Note that the <code>Selector</code> specified is cloned to protect
     * against subsequent modifications.
     *
     * @param selector a <code>Selector</code> specifying the constraints on
     *                 the target certificate or attribute certificate (or
     *                 <code>null</code>)
     * @see #getTargetConstraints
     * @see X509CertStoreSelector
     * @see X509AttributeCertStoreSelector
     */
    public void setTargetConstraints(Selector selector)
    {
        if (selector != null)
        {
            this.selector = (Selector)selector.clone();
        }
        else
        {
            this.selector = null;
        }
    }

    /**
     * Sets the required constraints on the target certificate. The constraints
     * are specified as an instance of <code>CertSelector</code>. If
     * <code>null</code>, no constraints are defined.
     * <p/>
     * <p/>
     * This method wraps the given <code>CertSelector</code> into a
     * <code>X509CertStoreSelector</code>.
     * <p/>
     * Note that the <code>CertSelector</code> specified is cloned to protect
     * against subsequent modifications.
     *
     * @param selector a <code>CertSelector</code> specifying the constraints
     *                 on the target certificate (or <code>null</code>)
     * @see #getTargetCertConstraints
     * @see X509CertStoreSelector
     */
    public void setTargetCertConstraints(CertSelector selector)
    {
        super.setTargetCertConstraints(selector);
        if (selector != null)
        {
            this.selector = X509CertStoreSelector
                .getInstance((X509CertSelector)selector);
        }
        else
        {
            this.selector = null;
        }
    }
}
