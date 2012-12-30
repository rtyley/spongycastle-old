package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * implementation of SHA-3 based on Keccak-simple.c from http://keccak.noekeon.org/
 * 
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHA3Digest implements ExtendedDigest {

    private static final int    cKeccakB               = 1600;
    private static final int    cKeccakR               = 1024;
    private static final int    cKeccakR_SizeInBytes   = (cKeccakR / 8); // 128
    private static final int    crypto_hash_BYTES      = cKeccakR_SizeInBytes;
    private static final int    cKeccakNumberOfRounds  = 24;

    private static final int    cKeccakLaneSizeInBits  = 64;            // size of a long
    private static final int    sizeofKeccakLane       = 8;

    private static final long[] KeccakF_RoundConstants = {
                    0x0000000000000001L,
                    0x0000000000008082L,
                    0x800000000000808aL,
                    0x8000000080008000L,
                    0x000000000000808bL,
                    0x0000000080000001L,
                    0x8000000080008081L,
                    0x8000000000008009L,
                    0x000000000000008aL,
                    0x0000000000000088L,
                    0x0000000080008009L,
                    0x000000008000000aL,
                    0x000000008000808bL,
                    0x800000000000008bL,
                    0x8000000000008089L,
                    0x8000000000008003L,
                    0x8000000000008002L,
                    0x8000000000000080L,
                    0x000000000000800aL,
                    0x800000008000000aL,
                    0x8000000080008081L,
                    0x8000000000008080L,
                    0x0000000080000001L,
                    0x8000000080008008L               };

    private static final int    DIGEST_LENGTH          = cKeccakR_SizeInBytes;
    private static final int    LANE_COUNT             = 16;

    //
    // registers
    //
    private long[]              _state                 = new long[5 * 5];

    //
    // input buffer, used for processing a whole block
    //
    private long[]              _x                    = new long[cKeccakR_SizeInBytes];
    private int                 _xOff                 = 0;

    // input buffer, used to create a block to be processed
    private byte[]              _buf                  = new byte[sizeofKeccakLane];
    private int                 _bufOff               = 0;
    
    private long                _byteCount            = 0;

    /**
     * Standard constructor
     */
    public SHA3Digest() {
        reset();
    }

    /**
     * Copy constructor. This will copy the state of the provided message digest.
     */
    public SHA3Digest(SHA3Digest t) {
        throw new IllegalStateException("Not yet implemented");
    }

    public String getAlgorithmName() {
        return "SHA3";
    }

    public int getDigestSize() {
        return DIGEST_LENGTH;
    }

    private void createInputState(byte[] b, int off) {
        _x[_xOff++] = ((long) (b[off + 7] & 0xff) << 56) | ((long) (b[off + 6] & 0xff) << 48)
                        | ((long) (b[off + 5] & 0xff) << 40) | ((long) (b[off + 4] & 0xff) << 32)
                        | ((long) (b[off + 3] & 0xff) << 24) | ((long) (b[off + 2] & 0xff) << 16)
                        | ((long) (b[off + 1] & 0xff) << 8) | ((b[off + 0] & 0xff));

        if (_xOff == _x.length) {
            processBlock(LANE_COUNT);
        }
        _bufOff = 0;
    }

    public void update(byte in) {
        _buf[_bufOff++] = in;

        if (_bufOff == _buf.length) {
            createInputState(_buf, 0);
        }

        _byteCount++;
    }

    public void update(byte[] in, int inOff, int len) {
        //
        // fill the current state
        //
        while ((_bufOff != 0) && (len > 0)) {
            update(in[inOff]);

            inOff++;
            len--;
        }

        //
        // process whole words.
        //
        while (len > 8) {
            createInputState(in, inOff);

            inOff += 8;
            len -= 8;
            _byteCount += 8;
        }

        //
        // load in the remainder.
        //
        while (len > 0) {
            update(in[inOff]);

            inOff++;
            len--;
        }
    }
    
    // yes I know these 2 are the same, but for the ease of debugging i want the
    // processBlock methods to look as much like the reference implementation as possible
    private final long ROL(long a, int offset) {
        return ((a << ((offset) % cKeccakLaneSizeInBits)) ^ (a >> (cKeccakLaneSizeInBits-((offset) % cKeccakLaneSizeInBits))));
    }
    
    private final long ROL_mult8(long a, int offset) {
        return ((a << ((offset) % cKeccakLaneSizeInBits)) ^ (a >> (cKeccakLaneSizeInBits-((offset) % cKeccakLaneSizeInBits))));        
    }
        

    private void processBlock(int laneCount) {
        // _state contains the current state
        // _x contains the state to be mixed in
        
        while ( -- laneCount >= 0 ) {
            _state[laneCount] ^= _x[laneCount];
        }
        
        long Aba, Abe, Abi, Abo, Abu;
        long Aga, Age, Agi, Ago, Agu;
        long Aka, Ake, Aki, Ako, Aku;
        long Ama, Ame, Ami, Amo, Amu;
        long Asa, Ase, Asi, Aso, Asu;
        long BCa, BCe, BCi, BCo, BCu;
        long Da, De, Di, Do, Du;
        long Eba, Ebe, Ebi, Ebo, Ebu;
        long Ega, Ege, Egi, Ego, Egu;
        long Eka, Eke, Eki, Eko, Eku;
        long Ema, Eme, Emi, Emo, Emu;
        long Esa, Ese, Esi, Eso, Esu;
        
        Aba = _state[0];
        Abe = _state[1];
        Abi = _state[2];
        Abo = _state[3];
        Abu = _state[4];
        Aga = _state[5];
        Age = _state[6];
        Agi = _state[7];
        Ago = _state[8];
        Agu = _state[9];
        Aka = _state[10];
        Ake = _state[11];
        Aki = _state[12];
        Ako = _state[13];
        Aku = _state[14];
        Ama = _state[15];
        Ame = _state[16];
        Ami = _state[17];
        Amo = _state[18];
        Amu = _state[19];
        Asa = _state[20];
        Ase = _state[21];
        Asi = _state[22];
        Aso = _state[23];
        Asu = _state[24];
        
        for (int round = 0; round < cKeccakNumberOfRounds; round+=2) {
            // prepare theta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;
            
            // thetoRhoPiChiIotaPrepareTheta(round, A, E)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);
            
            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba = BCa ^((~BCe)& BCi );
            Eba ^= KeccakF_RoundConstants[round];
            Ebe = BCe ^((~BCi)& BCo );
            Ebi = BCi ^((~BCo)& BCu );
            Ebo = BCo ^((~BCu)& BCa );
            Ebu = BCu ^((~BCa)& BCe );
            
            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka, 3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega = BCa ^((~BCe)& BCi );
            Ege = BCe ^((~BCi)& BCo );
            Egi = BCi ^((~BCo)& BCu );
            Ego = BCo ^((~BCu)& BCa );
            Egu = BCu ^((~BCa)& BCe );
            
            Abe ^= De;
            BCa = ROL(Abe, 1);
            Agi ^= Di;
            BCe = ROL(Agi, 6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL_mult8(Amu, 8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka = BCa ^((~BCe)& BCi );
            Eke = BCe ^((~BCi)& BCo );
            Eki = BCi ^((~BCo)& BCu );
            Eko = BCo ^((~BCu)& BCa );
            Eku = BCu ^((~BCa)& BCe );

            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL_mult8(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= KeccakF_RoundConstants[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL_mult8(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL_mult8(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        _state[ 0] = Aba;
        _state[ 1] = Abe;
        _state[ 2] = Abi;
        _state[ 3] = Abo;
        _state[ 4] = Abu;
        _state[ 5] = Aga;
        _state[ 6] = Age;
        _state[ 7] = Agi;
        _state[ 8] = Ago;
        _state[ 9] = Agu;
        _state[10] = Aka;
        _state[11] = Ake;
        _state[12] = Aki;
        _state[13] = Ako;
        _state[14] = Aku;
        _state[15] = Ama;
        _state[16] = Ame;
        _state[17] = Ami;
        _state[18] = Amo;
        _state[19] = Amu;
        _state[20] = Asa;
        _state[21] = Ase;
        _state[22] = Asi;
        _state[23] = Aso;
        _state[24] = Asu;            
            
    }

    public void unpackWord(long r, byte[] out, int outOff) {
        out[outOff + 7] = (byte) (r >> 56);
        out[outOff + 6] = (byte) (r >> 48);
        out[outOff + 5] = (byte) (r >> 40);
        out[outOff + 4] = (byte) (r >> 32);
        out[outOff + 3] = (byte) (r >> 24);
        out[outOff + 2] = (byte) (r >> 16);
        out[outOff + 1] = (byte) (r >> 8);
        out[outOff] = (byte) r;
    }

    private void processLength(long bitLength) {

    }

    private void finish() {
        long bitLength = (_byteCount << 3);

        update((byte) 0x01);

        while (_bufOff != 0) {
            update((byte)0);
        }

        processLength(bitLength);

        processBlock(LANE_COUNT);
    }

    public int doFinal(byte[] out, int outOff) {
        finish();

        // for (int i=0;i<_state.length;i++) {
        for (int i=0; i < 16; i++) {
            unpackWord(_state[i], out, outOff + (8*i));
        }

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the variables
     */
    public void reset() {
        _xOff = 0;
        for (int i = 0; i != _x.length; i++) {
            _x[i] = 0;
        }

        _bufOff = 0;
        for (int i = 0; i != _buf.length; i++) {
            _buf[i] = 0;
        }
        
        for (int i=0; i != _state.length; i++) {
            _state[i] = 0;
        }
        
        _byteCount = 0;
    }

    @Override
    public int getByteLength() {
        return 8;
    }

}
