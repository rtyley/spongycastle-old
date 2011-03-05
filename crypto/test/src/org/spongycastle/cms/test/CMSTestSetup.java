// Copyright (c) 2005 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
package org.spongycastle.cms.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

class CMSTestSetup extends TestSetup
{
    public CMSTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

}
