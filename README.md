The Spongy Castle repo has shifted...
======
_a repackage of Bouncy Castle for Android_

This is the **legacy** [Spongy Castle](http://rtyley.github.io/spongycastle/) repo - it used to sit
at [rtyley/spongycastle](https://github.com/rtyley/spongycastle) but is now renamed to
[rtyley/spongycastle-old](https://github.com/rtyley/spongycastle-old). When this repo was created back in
2011, the Bouncy Castle project wasn't on GitHub - in fact it was using CVS for source-control - so
this Spongy Castle repo was created with a `git cvsimport`.

The Bouncy Castle project moved to using an internal Git repo (rather than CVS) in 2013, and set up a
GitHub mirror at [bcgit/bc- java](https://github.com/bcgit/bc-java). Using GitHub to raise a pull-
request against this repo is now the best way to contribute patches to the Bouncy Castle project -
however, it's only possible to raise pull-requests using repos that are forks of the repo that's
receiving the pull-request.

Unfortunately, the original Spongy Castle repo couldn't be marked as a fork of the new [bcgit/bc-
java](https://github.com/bcgit/bc-java) repo, so it was renamed, and a *new* repo has been created
at [rtyley/spongycastle](https://github.com/rtyley/spongycastle) - as a 'proper' GitHub fork, I can
now use it to contribute patches to Bouncy Castle. Issues created against the original Spongy Castle
repo remain there, but should be copied and resumed on the new repo if they require updating.

