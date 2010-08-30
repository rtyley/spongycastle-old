package org.bouncycastle.operator;

import java.util.Date;

public interface DatedContentVerifier
    extends ContentVerifier
{
    /**
     * Returns the date before which the verifier should not be considered valid.
     *
     * @return date before which verifier is not valid.
     */
    Date getNotBefore();

    /**
     * Returns the date after which the verifier should not be considered valid.
     *
     * @return date after which verifier is not valid.
     */
    Date getNotAfter();

    /**
     * Return whether the passed in date is in the interval from notBefore to notAfter (inclusive).
     * @param date
     * @return
     */
    boolean checkValidity(Date date);
}