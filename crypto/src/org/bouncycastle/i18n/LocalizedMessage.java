package org.bouncycastle.i18n;

import org.bouncycastle.i18n.filter.Filter;
import org.bouncycastle.i18n.filter.UntrustedInput;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.Format;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.TimeZone;

public class LocalizedMessage 
{

    protected final String id;
    protected final String resource;
    
    // ISO-8859-1 is the default encoding
    public static final String DEFAULT_ENCODING = "ISO-8859-1";
    protected String encoding = DEFAULT_ENCODING;
    
    protected Object[] arguments;
    protected Object[] filteredArguments;
    
    protected Filter filter = null;
    
    protected ClassLoader loader = null;
    
    /**
     * Constructs a new LocalizedMessage using <code>resource</code> as the base name for the 
     * RessourceBundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @throws NullPointerException if <code>resource</code> or <code>id</code> is <code>null</code>
     */
    public LocalizedMessage(String resource,String id) throws NullPointerException
    {
        if (resource == null || id == null)
        {
            throw new NullPointerException();
        }
        this.id = id;
        this.resource = resource;
        this.arguments = new Object[0];
        this.filteredArguments = arguments;
    }
    
    /**
     * Constructs a new LocalizedMessage using <code>resource</code> as the base name for the 
     * RessourceBundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param encoding the encoding of the resource file
     * @throws NullPointerException if <code>resource</code> or <code>id</code> is <code>null</code>
     * @throws UnsupportedEncodingException if the encoding is not supported
     */
    public LocalizedMessage(String resource,String id, String encoding) throws NullPointerException, UnsupportedEncodingException
    {
        if (resource == null || id == null)
        {
            throw new NullPointerException();
        }
        this.id = id;
        this.resource = resource;
        this.arguments = new Object[0];
        this.filteredArguments = arguments;
        if (!Charset.isSupported(encoding))
        {
            throw new UnsupportedEncodingException("The encoding \"" + encoding + "\" is not supported.");
        }
        this.encoding = encoding;
    }
    
    /**
     * Constructs a new LocalizedMessage using <code>resource</code> as the base name for the 
     * RessourceBundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param arguments an array containing the arguments for the message
     * @throws NullPointerException if <code>resource</code> or <code>id</code> is <code>null</code>
     */
    public LocalizedMessage(String resource, String id, Object[] arguments) throws NullPointerException
    {
        if (resource == null || id == null || arguments == null)
        {
            throw new NullPointerException();
        }
        this.id = id;
        this.resource = resource;
        this.arguments = arguments;
        this.filteredArguments = arguments;
    }
    
    /**
     * Constructs a new LocalizedMessage using <code>resource</code> as the base name for the 
     * RessourceBundle and <code>id</code> as the message bundle id the resource file. 
     * @param resource base name of the resource file 
     * @param id the id of the corresponding bundle in the resource file
     * @param encoding the encoding of the resource file
     * @param arguments an array containing the arguments for the message
     * @throws NullPointerException if <code>resource</code> or <code>id</code> is <code>null</code>
     * @throws UnsupportedEncodingException if the encoding is not supported
     */
    public LocalizedMessage(String resource, String id, String encoding, Object[] arguments) throws NullPointerException, UnsupportedEncodingException
    {
        if (resource == null || id == null || arguments == null)
        {
            throw new NullPointerException();
        }
        this.id = id;
        this.resource = resource;
        this.arguments = arguments;
        this.filteredArguments = arguments;
        if (!Charset.isSupported(encoding))
        {
            throw new UnsupportedEncodingException("The encoding \"" + encoding + "\" is not supported.");
        }
        this.encoding = encoding;
    }
    
    /**
     * Reads the entry <code>id + "." + key</code> from the resource file and returns a 
     * formated message for the given Locale and TimeZone.
     * @param key second part of the entry id
     * @param loc the used {@link Locale}
     * @param timezone the used {@link TimeZone}
     * @return a Strng containing the localized message
     * @throws MissingEntryException if the resource file is not available or the entry does not exist.
     */
    public String getEntry(String key,Locale loc, TimeZone timezone) throws MissingEntryException
    {
        String entry = id + "." + key;
        
        try
        {
            ResourceBundle bundle;
            if (loader == null)
            {
                bundle = ResourceBundle.getBundle(resource,loc);
            }
            else
            {
                bundle = ResourceBundle.getBundle(resource, loc, loader);
            }
            String template = bundle.getString(entry);
            if (!encoding.equals(DEFAULT_ENCODING))
            {
                template = new String(template.getBytes(DEFAULT_ENCODING), encoding);
            }
            if (arguments == null || arguments.length == 0)
            {
                return template;
            }
            else
            {
                return formatWithTimeZone(template,filteredArguments,loc,timezone);
            }
        }
        catch (MissingResourceException mre)
        {
            throw new MissingEntryException("Can't find entry " + entry + " in resource file " + resource + ".",
                    resource,
                    entry,
                    loc,
                    loader != null ? loader : this.getClassLoader()); 
        }
        catch (UnsupportedEncodingException use)
        {
            // should never occur - cause we already test this in the constructor
            throw new RuntimeException(use);
        }
    }
    
    protected String formatWithTimeZone(
            String template,
            Object[] arguments, 
            Locale locale,
            TimeZone timezone) 
    {
        MessageFormat mf = new MessageFormat(" ");
        mf.setLocale(locale);
        mf.applyPattern(template);
        if (!timezone.equals(TimeZone.getDefault())) 
        {
            Format[] formats = mf.getFormats();
            for (int i = 0; i < formats.length; i++) 
            {
                if (formats[i] instanceof DateFormat) 
                {
                    DateFormat temp = (DateFormat) formats[i];
                    temp.setTimeZone(timezone);
                    mf.setFormat(i,temp);
                }
            }
        }
        return mf.format(arguments);
    }
    
    /**
     * Sets the {@link Filter} that is used to filter the arguments of this message
     * @param filter the {@link Filter} to use. <code>null</code> to disable filtering.
     */
    public void setFilter(Filter filter)
    {
        if (filter == null)
        {
            filteredArguments = arguments;
        }
        else if (!filter.equals(this.filter))
        {
            filteredArguments = new Object[arguments.length];
            for (int i = 0; i < arguments.length; i++)
            {
                if (arguments[i] instanceof UntrustedInput) 
                {
                    filteredArguments[i] = filter.doFilter(((UntrustedInput) arguments[i]).getString());
                }
                else
                {
                    filteredArguments[i] = arguments[i];
                }
            }
        }
        this.filter = filter;
    }
    
    /**
     * Returns the current filter.
     * @return the current filter
     */
    public Filter getFilter()
    {
        return filter;
    }
    
    /**
     * Set the {@link ClassLoader} which loads the resource files. If it is set to <code>null</code>
     * then the default {@link ClassLoader} is used. 
     * @param loader the {@link ClassLoader} which loads the resource files
     */
    public void setClassLoader(ClassLoader loader)
    {
        this.loader = loader;
    }
    
    /**
     * Returns the {@link ClassLoader} which loads the resource files or <code>null</code>
     * if the default ClassLoader is used.
     * @return the {@link ClassLoader} which loads the resource files
     */
    public ClassLoader getClassLoader()
    {
        return loader;
    }
    
    /**
     * Returns the id of the message in the resource bundle.
     * @return the id of the message
     */
    public String getId()
    {
        return id;
    }
    
    /**
     * Returns the name of the resource bundle for this message
     * @return name of the resource file
     */
    public String getResource()
    {
        return resource;
    }
    
    /**
     * Returns an <code>Object[]</code> containing the message arguments.
     * @return the message arguments
     */
    public Object[] getArguments()
    {
        return arguments;
    }
    
}
