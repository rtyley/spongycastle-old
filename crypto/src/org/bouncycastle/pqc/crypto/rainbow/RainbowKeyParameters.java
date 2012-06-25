package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class RainbowKeyParameters 
    extends AsymmetricKeyParameter
{
	private RainbowParameters    params;

	public RainbowKeyParameters(
			boolean         isPrivate,
			RainbowParameters   params)
	{
		super(isPrivate);
		this.params = params;
	}   

	public RainbowParameters getParameters()
	{
		return params;
	}
}
