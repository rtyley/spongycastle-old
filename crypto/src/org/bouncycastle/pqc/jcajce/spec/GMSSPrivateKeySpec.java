package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.GMSSLeaf;
import org.bouncycastle.pqc.crypto.gmss.GMSSParameters;
import org.bouncycastle.pqc.crypto.gmss.GMSSRootCalc;
import org.bouncycastle.pqc.crypto.gmss.GMSSRootSig;
import org.bouncycastle.pqc.crypto.gmss.Treehash;


/**
 * This class provides a specification for a GMSS private key.
 *
 * @see org.bouncycastle.pqc.jcajce.provider.JDKGMSSPrivateKey.GMSSPrivateKey
 */
public class GMSSPrivateKeySpec
    implements KeySpec
{

    private int[] index;

    private byte[][] currentSeed;
    private byte[][] nextNextSeed;

    private byte[][][] currentAuthPath;
    private byte[][][] nextAuthPath;

    private Treehash[][] currentTreehash;
    private Treehash[][] nextTreehash;

    private Vector[] currentStack;
    private Vector[] nextStack;

    private Vector[][] currentRetain;
    private Vector[][] nextRetain;

    private byte[][][] keep;

    private GMSSLeaf[] nextNextLeaf;
    private GMSSLeaf[] upperLeaf;
    private GMSSLeaf[] upperTreehashLeaf;

    private int[] minTreehash;

    private GMSSParameters gmssPS;

    private byte[][] nextRoot;
    private GMSSRootCalc[] nextNextRoot;

    private byte[][] currentRootSig;
    private GMSSRootSig[] nextRootSig;

    private Class<? extends Digest> digestClass;


    /**
     * @param index             tree indices
     * @param currentSeed       seed for the generation of private OTS keys for the
     *                          current subtrees (TREE)
     * @param nextNextSeed      seed for the generation of private OTS keys for the
     *                          subtrees after next (TREE++)
     * @param currentAuthPath   array of current authentication paths (AUTHPATH)
     * @param nextAuthPath      array of next authentication paths (AUTHPATH+)
     * @param keep              keep array for the authPath algorithm
     * @param currentTreehash   treehash for authPath algorithm of current tree
     * @param nextTreehash      treehash for authPath algorithm of next tree (TREE+)
     * @param currentStack      shared stack for authPath algorithm of current tree
     * @param nextStack         shared stack for authPath algorithm of next tree (TREE+)
     * @param currentRetain     retain stack for authPath algorithm of current tree
     * @param nextRetain        retain stack for authPath algorithm of next tree (TREE+)
     * @param nextNextLeaf      array of upcoming leafs of the tree after next (LEAF++) of
     *                          each layer
     * @param upperLeaf         needed for precomputation of upper nodes
     * @param upperTreehashLeaf needed for precomputation of upper treehash nodes
     * @param minTreehash       index of next treehash instance to receive an update
     * @param nextRoot          the roots of the next trees (ROOT+)
     * @param nextNextRoot      the roots of the tree after next (ROOT++)
     * @param currentRootSig    array of signatures of the roots of the current subtrees
     *                          (SIG)
     * @param nextRootSig       array of signatures of the roots of the next subtree
     *                          (SIG+)
     * @param gmssParameterset  the GMSS Parameterset
     * @param digestClass       An array of strings, containing the name of the used hash
     *                          function and the name of the corresponding provider
     */
    public GMSSPrivateKeySpec(int[] index, byte[][] currentSeed,
                              byte[][] nextNextSeed, byte[][][] currentAuthPath,
                              byte[][][] nextAuthPath, Treehash[][] currentTreehash,
                              Treehash[][] nextTreehash, Vector[] currentStack,
                              Vector[] nextStack, Vector[][] currentRetain,
                              Vector[][] nextRetain, byte[][][] keep, GMSSLeaf[] nextNextLeaf,
                              GMSSLeaf[] upperLeaf, GMSSLeaf[] upperTreehashLeaf,
                              int[] minTreehash, byte[][] nextRoot, GMSSRootCalc[] nextNextRoot,
                              byte[][] currentRootSig, GMSSRootSig[] nextRootSig,
                              GMSSParameters gmssParameterset, Class<? extends Digest> algNames)
    {
        this.index = index;
        this.currentSeed = currentSeed;
        this.nextNextSeed = nextNextSeed;
        this.currentAuthPath = currentAuthPath;
        this.nextAuthPath = nextAuthPath;
        this.currentTreehash = currentTreehash;
        this.nextTreehash = nextTreehash;
        this.currentStack = currentStack;
        this.nextStack = nextStack;
        this.currentRetain = currentRetain;
        this.nextRetain = nextRetain;
        this.keep = keep;
        this.nextNextLeaf = nextNextLeaf;
        this.upperLeaf = upperLeaf;
        this.upperTreehashLeaf = upperTreehashLeaf;
        this.minTreehash = minTreehash;
        this.nextRoot = nextRoot;
        this.nextNextRoot = nextNextRoot;
        this.currentRootSig = currentRootSig;
        this.nextRootSig = nextRootSig;
        this.gmssPS = gmssParameterset;
        this.digestClass = algNames;
    }

    public int[] getIndex()
    {
        return index.clone();
    }

    public byte[][] getCurrentSeed()
    {
        return currentSeed.clone();
    }

    public byte[][] getNextNextSeed()
    {
        return nextNextSeed.clone();
    }

    public byte[][][] getCurrentAuthPath()
    {
        return currentAuthPath.clone();
    }

    public byte[][][] getNextAuthPath()
    {
        return nextAuthPath.clone();
    }

    public Treehash[][] getCurrentTreehash()
    {
        return currentTreehash.clone();
    }

    public Treehash[][] getNextTreehash()
    {
        return nextTreehash.clone();
    }

    public byte[][][] getKeep()
    {
        return keep.clone();
    }

    public Vector[] getCurrentStack()
    {
        return currentStack.clone();
    }

    public Vector[] getNextStack()
    {
        return nextStack.clone();
    }

    public Vector[][] getCurrentRetain()
    {
        return currentRetain.clone();
    }

    public Vector[][] getNextRetain()
    {
        return nextRetain.clone();
    }

    public GMSSLeaf[] getNextNextLeaf()
    {
        return nextNextLeaf.clone();
    }

    public GMSSLeaf[] getUpperLeaf()
    {
        return upperLeaf.clone();
    }

    public GMSSLeaf[] getUpperTreehashLeaf()
    {
        return upperTreehashLeaf.clone();
    }

    public int[] getMinTreehash()
    {
        return minTreehash.clone();
    }

    public GMSSRootSig[] getNextRootSig()
    {
        return nextRootSig.clone();
    }

    public GMSSParameters getGmssPS()
    {
        return gmssPS;
    }

    public byte[][] getNextRoot()
    {
        return nextRoot.clone();
    }

    public GMSSRootCalc[] getNextNextRoot()
    {
        return nextNextRoot.clone();
    }

    public byte[][] getCurrentRootSig()
    {
        return currentRootSig.clone();
    }

    public Class<? extends Digest> getAlgNames()
    {
        return digestClass;
    }


}