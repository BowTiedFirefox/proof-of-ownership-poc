# Proof of ownership

## Introduction

+ Goal: A way to give a user *U* the ability to prove possession of an NFT of
  type *N* without submitting his address
+ How to tl;dr: ring signature of a random message sent by the verifier
+ We can identify a user with its own address

In the following we explain a way to ring-signature a message on Ethereum

## Ring signatures

Generally a digital signature scheme uses a private key to sign a message. The
user *U* sends the signature *\sigma* and the message *m* to a verifier *V*.
*V* uses the public key of *U* to decrypt *\sigma* obtaining *m\prime*. If
*m==m\prime* then *V* accepts the signature. Otherwise *V* refuses it.

Note: a signature is basically a proof of knowledge of a private key. That can
be leveraged by having *V* to create a random message and *U* to sign it. After
the signing routine, *V* is certain (up to a negligible probability) that *U*
has a private key. This is currently used in many blockchains as a proof of
ownership of an address.

But what if a prover *P* wants to prove he owns and address out of many? Enter
the ring-signatures.

Ring signatures let user *U* prove he owns one address among addresses
*U,A_1,...,A_k*. *V* can just verify that, he won't know _which_ of these
addresses *U* is the owner of.

## Pubkeys in Ethereum

Public keys in Ethereum can be obtained from a transaction. That is because the
version of the ECDSA signature used by ETH also has a *v* parameter in addition
to the usual *r* and *s*.

## Use cases and Don't-Use Cases

This can be leveraged for any kind of possessions. Some examples:

- proof of ownership of at least 1ETH: just be sure addresses
  *U,A_1,...,A_k* own 1ETH each
- proof of ownership of more than 1ETH: just be sure addresses
  *U,A_1,...,A_k* own more than 1ETH each
- proof of ownership of a hashmask: just be sure addresses *U,A_1,...,A_k*
  own at least one hashmask


What you **can't** prove though:

- proof of ownership of a **specific** hashmask
- proof of ownership of a **1:1 NFT**

## Proof of concept

User *P*, the prover, needs to prove he owns at least 0.01ETH. *P* is both the
address and the user, and we assume that the public key of *P* is *pk_0*.
Assume there are addresses *A_1,...,A_k*, each of them owning at least
0.01ETH. Let *V* be a verifier.

1. *V* creates a random message *m*.
1. Then *P* starts and for each address *A_1,...,A_k* *P* collects a
   transaction hash *th_1,...,th_k*.
1. From each transaction hash, *P* gets pubkeys *pk_1,...,pk_k*. Then *P*
   creates a ring signature with his private key *sk* and public keys
   *pk_0,pk_1,...,pk_k*. Note there are *k+1* public keys in total. This part is
   done by the script which outputs a signature *\sigma* of message *m*
1. *P* sends *\sigma* and *pk_0,pk_1,...,pk_k* to *V*
1. *V* verifies that *\sigma* is the signature of *m* and if so *V* knows that
   *P* is the owner of one address among *P,A_1,...,A_k*, but he doesn't
   know which one



