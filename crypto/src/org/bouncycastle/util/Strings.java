package org.bouncycastle.util;

public final class Strings
{
    /**
     * A locale independent version of toUpperCase.
     * 
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(String string)
    {
        boolean changed = false;
        char[] chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++)
        {
            char ch = chars[i];
            if ('a' <= ch && 'z' >= ch)
            {
                changed = true;
                chars[i] = (char)(ch - 'a' + 'A');
            }
        }
        
        if (changed)
        {
            return new String(chars);
        }
        
        return string;
    }
    
    /**
     * A locale independent version of toLowerCase.
     * 
     * @param string input to be converted
     * @return a US ASCII lowercase version
     */
    public static String toLowerCase(String string)
    {
        boolean changed = false;
        char[] chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++)
        {
            char ch = chars[i];
            if ('A' <= ch && 'Z' >= ch)
            {
                changed = true;
                chars[i] = (char)(ch - 'A' + 'a');
            }
        }
        
        if (changed)
        {
            return new String(chars);
        }
        
        return string;
    }
}
