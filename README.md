## Schnorr NIZK using Curve25519

A Java implementation of the [Schnorr protocol](https://en.wikipedia.org/wiki/Proof_of_knowledge#Schnorr_protocol) using Curve25519.

Schnorr NIZK allows proving the knowledge of a discrete logarithm without revealing its value. As a sample, this can be used to prove that a party knows the hash of a certain piece of data to a challenger without revealing it in the process.

Part of [Weavechain](https://weavechain.com): The Layer-0 For Data

### Usage

#### Gradle Groovy DSL

```
implementation 'com.weavechain:schnorr-nizk:1.0'
```

#### Gradle Kotlin DSL

```
implementation("com.weavechain:schnorr-nizk:1.0")
```

##### Apache Maven

```xml
<dependency>
  <groupId>com.weavechain</groupId>
  <artifactId>schnorr-nizk</artifactId>
  <version>1.0</version>
</dependency>
```

#### Sample

```java
String text = "test1234567890";

//challenger
byte[] commitment = new byte[64];
SchnorrNIZK.random().nextBytes(commitment);

//data owner
Scalar k = SchnorrNIZK.hashScalar(text, commitment);
Transcript transcript = SchnorrNIZK.prove(k);

byte[] hash = k.toByteArray();
String serialization = Base58.encode(transcript.toBytes());

//verification by challenger, assuming the hash is known or can be computed
Transcript deserialized = Transcript.fromBase58(serialization);
Scalar kv = Scalar.fromBits(hash);

boolean match = SchnorrNIZK.verify(kv, deserialized);
System.out.println(match ? "Success" : "Fail");
```

#### Weavechain

Read more about Weavechain at [https://docs.weavechain.com](https://docs.weavechain.com)