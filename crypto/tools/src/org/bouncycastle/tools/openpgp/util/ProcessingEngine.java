package org.spongycastle.tools.openpgp.util;

import java.util.Collection;

/**
 * 
 */
public interface ProcessingEngine
{
    public void process();
    
    public boolean isError();
    public Collection errorMessages();
    
}