package org.bouncycastle.util.test;

public class SimpleTestResult implements TestResult
{
    private static final String SEPARATOR = System.getProperty("line.separator");

    private boolean             success;
    private String              message;
    private Exception           exception;

    public SimpleTestResult(boolean success, String message)
    {
        this.success = success;
        this.message = message;
    }

    public SimpleTestResult(boolean success, String message, Exception exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static TestResult successful(String message)
    {
        return new SimpleTestResult(true, message);
    }

    public static TestResult failed(String message)
    {
        return new SimpleTestResult(false, message);
    }

    public static String failedMessage(String algorithm, String testName, String expected,
            String actual)
    {
        StringBuffer sb = new StringBuffer(algorithm);
        sb.append(" failing ").append(testName);
        sb.append(SEPARATOR).append("    expected: ").append(expected);
        sb.append(SEPARATOR).append("    got     : ").append(actual);

        return sb.toString();
    }

    public boolean isSuccessful()
    {
        return success;
    }

    public String toString()
    {
        return message;
    }

    public Exception getException()
    {
        return exception;
    }
}
