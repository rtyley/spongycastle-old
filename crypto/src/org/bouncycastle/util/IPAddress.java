package org.bouncycastle.util;

import java.util.StringTokenizer;

public class IPAddress
{
    /**
     * Validate the given IPv4 or IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid address, false otherwise
     */
    public static boolean isValid(
        String address)
    {
        return isValidIPv4(address) || isValidIPv6(address);
    }

    /**
     * Validate the given IPv4 or IPv6 address and netmask.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid address with netmask, false otherwise
     */
    public static boolean isValidWithNetMask(
        String address)
    {
        return isValidIPv4WithNetmask(address) || isValidIPv6WithNetmask(address);
    }

    /**
     * Validate the given IPv4 address.
     * 
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv4 address, false otherwise
     */
    private static boolean isValidIPv4(
        String address)
    {
        if (address.length() == 0)
        {
            return false;
        }

        int octet;
        int octets = 0;
        
        String temp = address+".";

        int pos;
        int start = 0;
        while (start < temp.length()
            && (pos = temp.indexOf('.', start)) > start)
        {
            if (octets == 4)
            {
                return false;
            }
            try
            {
                octet = Integer.parseInt(temp.substring(start, pos));
            }
            catch (NumberFormatException ex)
            {
                return false;
            }
            if (octet < 0 || octet > 255)
            {
                return false;
            }
            start = pos + 1;
            octets++;
        }

        return octets == 4;
    }

    public static boolean isValidIPv4WithNetmask(
        String address)
    {
        int index = address.indexOf("/");
        String mask = address.substring(index + 1);

        return (index > 0) && isValidIPv4(address.substring(0, index))
                           && (isValidIPv4(mask) || isMaskValue(mask, 32));
    }

    public static boolean isValidIPv6WithNetmask(
        String address)
    {
        int index = address.indexOf("/");
        String mask = address.substring(index + 1);

        return (index > 0) && (isValidIPv6(address.substring(0, index))
                           && (isValidIPv6(mask) || isMaskValue(mask, 128)));
    }

    private static boolean isMaskValue(String component, int size)
    {
        try
        {
            int value = Integer.parseInt(component);

            return value >= 0 && value <= size;
        }
        catch (NumberFormatException e)
        {
            return false;
        }
    }

    /**
     * Validate the given IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv4 address, false otherwise
     */
    private static boolean isValidIPv6(
        String address)
    {
        if (address.length() == 0)
        {
            return false;
        }

        int octet;
        int octets = 0;

        String temp = address + ":";
        boolean doubleColonFound = false;
        int pos;
        int start = 0;
        while (start < temp.length()
            && (pos = temp.indexOf(':', start)) >= start)
        {
            if (octets == 8)
            {
                return false;
            }

            if (start != pos)
            {
                String value = temp.substring(start, pos);

                if (pos == (temp.length() - 1) && value.indexOf('.') > 0)
                {
                    if (!isValidIPv4(value))
                    {
                        return false;
                    }

                    octets++; // add an extra one as address covers 2 words.
                }
                else
                {
                    try
                    {
                        octet = Integer.parseInt(temp.substring(start, pos), 16);
                    }
                    catch (NumberFormatException ex)
                    {
                        return false;
                    }
                    if (octet < 0 || octet > 0xffff)
                    {
                        return false;
                    }
                }
            }
            else
            {
                if (pos != 1 && pos != temp.length() - 1 && doubleColonFound)
                {
                    return false;
                }
                doubleColonFound = true;
            }
            start = pos + 1;
            octets++;
        }

        return octets == 8 || doubleColonFound;
    }

    /**
     * Return a byte encoding suitable for use in a GeneralName
     *
     * @param ip address (may be ipv4 or ipv6)
     * @return a byte encoding
     */
    public static byte[] toGeneralNameEncoding(String ip)
    {
        if (isValidIPv6WithNetmask(ip) || isValidIPv6(ip))
        {
            int    slashIndex = ip.indexOf('/');

            if (slashIndex < 0)
            {
                byte[] addr = new byte[16];
                int[]  parsedIp = parseIPv6(ip);
                copyInts(parsedIp, addr, 0);

                return addr;
            }
            else
            {
                byte[] addr = new byte[32];
                int[]  parsedIp = parseIPv6(ip.substring(0, slashIndex));
                copyInts(parsedIp, addr, 0);
                String mask = ip.substring(slashIndex + 1);
                if (mask.indexOf(':') > 0)
                {
                    parsedIp = parseIPv6(mask);
                }
                else
                {
                    parsedIp = parseMask(mask);
                }
                copyInts(parsedIp, addr, 16);

                return addr;
            }
        }
        else if (isValidIPv4WithNetmask(ip) || isValidIPv4(ip))
        {
            int    slashIndex = ip.indexOf('/');

            if (slashIndex < 0)
            {
                byte[] addr = new byte[4];

                parseIPv4(ip, addr, 0);

                return addr;
            }
            else
            {
                byte[] addr = new byte[8];

                parseIPv4(ip.substring(0, slashIndex), addr, 0);

                String mask = ip.substring(slashIndex + 1);
                if (mask.indexOf('.') > 0)
                {
                    parseIPv4(mask, addr, 4);
                }
                else
                {
                    parseIPv4Mask(mask, addr, 4);
                }

                return addr;
            }
        }

        return null;
    }

    private static void parseIPv4Mask(String mask, byte[] addr, int offset)
    {
        int   maskVal = Integer.parseInt(mask);

        for (int i = 0; i != maskVal; i++)
        {
            addr[(i / 8) + offset] |= 1 << (i % 8);
        }
    }

    private static void parseIPv4(String ip, byte[] addr, int offset)
    {
        StringTokenizer sTok = new StringTokenizer(ip, "./");
        int    index = 0;

        while (sTok.hasMoreTokens())
        {
            addr[offset + index++] = (byte)Integer.parseInt(sTok.nextToken());
        }
    }

    private static int[] parseMask(String mask)
    {
        int[] res = new int[8];
        int   maskVal = Integer.parseInt(mask);

        for (int i = 0; i != maskVal; i++)
        {
            res[i / 16] |= 1 << (i % 16);
        }
        return res;
    }

    private static void copyInts(int[] parsedIp, byte[] addr, int offSet)
    {
        for (int i = 0; i != parsedIp.length; i++)
        {
            addr[(i * 2) + offSet] = (byte)(parsedIp[i] >> 8);
            addr[(i * 2 + 1) + offSet] = (byte)parsedIp[i];
        }
    }

    private static int[] parseIPv6(String ip)
    {
        StringTokenizer sTok = new StringTokenizer(ip, ":", true);
        int index = 0;
        int[] val = new int[8];

        if (ip.charAt(0) == ':' && ip.charAt(1) == ':')
        {
           sTok.nextToken(); // skip the first one
        }

        int doubleColon = -1;

        while (sTok.hasMoreTokens())
        {
            String e = sTok.nextToken();

            if (e.equals(":"))
            {
                doubleColon = index;
                val[index++] = 0;
            }
            else
            {
                if (e.indexOf('.') < 0)
                {
                    val[index++] = Integer.parseInt(e, 16);
                    if (sTok.hasMoreTokens())
                    {
                        sTok.nextToken();
                    }
                }
                else
                {
                    StringTokenizer eTok = new StringTokenizer(e, ".");

                    val[index++] = (Integer.parseInt(eTok.nextToken()) << 8) | Integer.parseInt(eTok.nextToken());
                    val[index++] = (Integer.parseInt(eTok.nextToken()) << 8) | Integer.parseInt(eTok.nextToken());
                }
            }
        }

        if (index != val.length)
        {
            System.arraycopy(val, doubleColon, val, val.length - (index - doubleColon), index - doubleColon);
            for (int i = doubleColon; i != val.length - (index - doubleColon); i++)
            {
                val[i] = 0;
            }
        }

        return val;
    }
}


