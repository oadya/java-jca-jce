package com.cryptography.jca;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TestSecurity {

	public static void main(String[] args) throws Exception{
		// testSecurity();
		
		//testMessageDigest();
		
		// testSignature();
		
		//testKeyStore();
		
		//testKeyPairGenerator();
		
		// testKeyFactory();
		
		// testCertificateFactory();
		
		//testKeyGenerator();
		
		//testSecretKeyFactory();
		
		// testCipher();
		
		//testCipherWrap();
		
		//testCipherGetParameters();
		
		//testCipherDES_AES();
		
		testMac();

	}
	
	private  static void testSecurity(){
		// La classe java.security.Security permet de gérer les fournisseurs de services en enregistrant ou en retirant une implémentation. 
		// Elle permet aussi d'obtenir la liste des fournisseurs enregistrés.
		
		System.out.println("\n/************* les fournisseurs de services**********************/\n");
		// Renvoyer un tableau des fournisseurs 
		Provider[] providers = Security.getProviders();
		
		for (Provider provider : providers) {
		      System.out.println("Provider : " + provider.getName() + " v"
		          + provider.getVersion());
		    }
		 System.out.println("\n/************* les services du fournisseur SunJCE **********************/\n");
		 
		// L'exemple ci-dessous, affiche tous les services du fournisseur SunJCE fourni en standard avec le JDK de Sun.
		 Provider provider = Security.getProvider("SunJCE");
		 
		 
		  System.out.println("Services du provider " + provider.getName());
		    for (Service service : provider.getServices()) {
		      System.out.println("\t" + service.getType() + " "
		          + service.getAlgorithm());
		    }
		    
		    System.out.println("\n/*************** getAlgorithms() renvoie un ensemble de noms d'algorithmes  d'un type de service  ********************/\n");
		    
		    // La méthode getAlgorithms() attend en paramètre le nom d'un type de service (Signature, MessageDigest, Cipher, Mac, KeyStore, ...) 
		    // et renvoie un ensemble de noms d'algorithmes disponibles auprès des différents providers enregistrés.
		    System.out.println("Algorithmes d'un tye de service \n");
		    for (String algo : Security.getAlgorithms("Cipher")) {
		        System.out.println(algo);
		      }
		
	}
	
	private  static void testMessageDigest(){
		
		 String monMessage = "Mon message";

		    calculerValeurDeHachage("MD2", monMessage);
		    calculerValeurDeHachage("MD5", monMessage);
		    calculerValeurDeHachage("SHA-1", monMessage);
		    calculerValeurDeHachage("SHA-256", monMessage);
		    calculerValeurDeHachage("SHA-384", monMessage);
		    calculerValeurDeHachage("SHA-512", monMessage);
		    
		    
		    // Les classes java.security.DigestInputStream et java.security.DigestOuputStream
		    //  permettent de calculer une valeur de hachage pour des octets contenus dans un flux
		    testDigestInputStream();
		    
		    testDigestOutputStream();
		    
		
		
	}
	
	
	  public static byte[] calculerValeurDeHachage(String algorithme,
		      String monMessage) {
		    byte[] digest = null;
		    try {
		    	// La méthode statique getInstance() permet de demander l'implémentation d'un algorithme particulier 
		      MessageDigest sha = MessageDigest.getInstance(algorithme);
		      
		      // la méthode digest() calcule la valeur de hachage pour les données fournies.
		      digest = sha.digest(monMessage.getBytes());
		      
		      System.out.println("algorithme : " + algorithme);
		      System.out.println(ConvertionHelper.bytesToHex(digest));
		    } catch (NoSuchAlgorithmException e) {
		      e.printStackTrace();
		    }
		    return digest;

		  }
	  
	  
	  public static void testDigestInputStream () {
		  
		    InputStream is;
		    DigestInputStream dis = null;
		    try {
		      is = new BufferedInputStream(new FileInputStream("src/main/resources/monfichier.txt"));
		      MessageDigest md = MessageDigest.getInstance("SHA-1");

		      dis = new DigestInputStream(is, md);

		      byte[] buffer = new byte[64];
		      while (dis.read(buffer) != -1)
		        ;

		    } catch (FileNotFoundException e) {
		      e.printStackTrace();
		    } catch (NoSuchAlgorithmException e) {
		      e.printStackTrace();
		    } catch (IOException e) {
		      e.printStackTrace();
		    } finally {
		      if (dis != null) {
		        try {
		          dis.close();
		          byte[] hash = dis.getMessageDigest().digest();
		          System.out.println("\n ******** DigestInputStream *************  \n");
		          System.out.println(ConvertionHelper.bytesToHex(hash));
		        } catch (IOException e) {
		          e.printStackTrace();
		        }
		      }
		    }
		  
	  }
	  
	  public static void testDigestOutputStream  () {
		  
		  
		    byte[] donnees = "Hello World".getBytes();

		    FileOutputStream fop = null;
		    File file;
		    DigestOutputStream dos = null;

		    try {
		      MessageDigest md = MessageDigest.getInstance("SHA-512");

		      file = new File("src/main/resources/monfichier-output.txt");
		      fop = new FileOutputStream(file);

		      dos = new DigestOutputStream(fop, md);
		      dos.write(donnees);
		    } catch (IOException e) {
		      e.printStackTrace();
		    } catch (NoSuchAlgorithmException e) {
		      e.printStackTrace();
		    } finally {
		      try {
		        if (dos != null) {
		          dos.close();
		          byte[] hash = dos.getMessageDigest().digest();
		          System.out.println("\n ******** DigestOutputStream *************  \n");
		          System.out.println(ConvertionHelper.bytesToHex(hash));
		        }
		      } catch (IOException e) {
		        e.printStackTrace();
		      }
		    }
	  }
	  
	  
	  private  static void testSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		  
		  //La classe java.security.Signature Elle permet de signer des données et de vérifier des données signées. 
		  
		  //Pour créer une signature digitale, il faut instancier un objet de type Signature et l'initialiser avec une clé privée. Les données sont fournies à l'objet Signature pour créer la signature.

		  //Pour vérifier la signature, il faut créer un objet de type Signature et l'initialiser avec la clé publique. Les données et la signature sont fournies à l'objet Signature pour vérification.
	      //    les états : UNINITIALIZED , SIGN, VERIFY
		  
	/*	  La méthode initSign() attend en paramètre un objet de type PrivateKey qui encapsule la clé privée pour signer des données.

		    void initSign(PrivateKey privateKey)

		La méthode initVerify() possède deux surcharges qui attendent respectivement en paramètre :

		    un objet de type PublicKey qui encapsule la clé publique : void initVerify(PublicKey publicKey)
		    un objet de type Certificate qui encapsule le certificat : void initVerify(Certificate certificate)*/
		  
		  byte[] message = "Hello world".getBytes();

//		  La classe KeyPair encapsule une paire de clés : une clé publique et une clé privée.
//
//		      PrivateKey getPrivate() : obtenir la clé privée
//		      PublicKey getPublic() : obtenir la clé publique

		    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		    keyPairGen.initialize(1024, new SecureRandom());
		    KeyPair keyPair = keyPairGen.generateKeyPair();

		    //Pour obtenir une instance de type Signature avec un algorithme spécifique,
		    Signature signature = Signature.getInstance("SHA1withRSA");
		    
		    //il faut l'initialiser dans un mode de fonctionnement - >permettent de passer l'état à SIGN
		    signature.initSign(keyPair.getPrivate(), new SecureRandom());
		    
		    //Les données doivent être fournies en utilisant une des surcharges de la méthode update()
		    signature.update(message);
		    
		    //Pour générer la signature des données avec la clé
		    byte[] signatureBytes = signature.sign();
		    System.out.println("\n ******** Signature des données *************  \n");
		    System.out.println(ConvertionHelper.bytesToHex(signatureBytes));
		   
		    
		    System.out.println("\n ******** Virification Signature des données *************  \n");
		    //il faut l'initialiser dans un mode de fonctionnement - >permettent de passer l'état à VERIFY
		    signature.initVerify(keyPair.getPublic());
		    signature.update(message);
		    
		    // la méthode verify() qui renvoie un booléen indiquant si oui ou non la signature encodée est la signature authentique des données fournies grâce à la méthode update() :
		    boolean result = signature.verify(signatureBytes) ;
		    System.out.println(result );
		    

		    

	  }
	  
	  private  static void testKeyStore(){
		  
		  // La classe KeyStore permet de stocker, gérer et récupérer les éléments contenus dans un dépôt de clés :  des clés et des certificats
		  // Chaque élément contenu dans un keyStore est identifié par un alias unique.
		  
		  char[] mdp = { '1', '2', '3', '4', '5', '6' };

		    FileInputStream is;
		    try {
		      is = new FileInputStream("c:/java/jmPrivateKey.store");
		      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		      keystore.load(is, mdp);

		      String alias = "jmTrustKey";
		      Certificate cert = keystore.getCertificate(alias);

		      System.out.println(cert);

		    } catch (Exception e) {
		      e.printStackTrace();
		    }
		    
		    /***********************************************/
		    
		    char[] mdpDepot = { '1', '2', '3', '4', '5', '6' };
		    char[] mdpCle = { 'a', 'b', 'c', 'd', 'e', 'f' };

		    FileInputStream iss;
		    try {
		      iss = new FileInputStream("c:/java/jmPrivateKey.store");
		      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		      keystore.load(iss, mdpDepot);

		      KeyPair cles = getPrivateKey(keystore, "jmTrustKey", mdpCle);

		    } catch (Exception e) {
		      e.printStackTrace();
		    }
		  
		  
	  }
	  
	  public static KeyPair getPrivateKey(KeyStore keystore, String alias, char[] password)
		      throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		    KeyPair resultat = null;

		    // Obtenir la clé correspondant à l'alias fourni en paramètre. Le mot de passe fourni en paramètre doit être celui associé à la protection de la clé.
		    // Les objets de type Key (clé opaque) et KeySpec (clé transparente) sont deux représentations des données d'une clé. 
		    Key clePrivee = keystore.getKey(alias, password);
		    
		    if (clePrivee instanceof PrivateKey) {
		      Certificate cert = keystore.getCertificate(alias);
		      PublicKey clePublique = cert.getPublicKey();
		      resultat =  new KeyPair(clePublique, (PrivateKey) clePrivee);
		    }
		    return resultat;
		  }
	  
	  private  static void testKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException{
//		  La classe KeyPairGenerator permet de générer une paire de clés : une publique et une privée.
//
//		  La génération d'une paire de clés peut se faire de deux manières :
//
//		      de manière indépendante de tout algorithme
//		      de manière spécifique à un algorithme : dans ce cas, la seule différence est la nécessité d'initialiser l'objet.

		  KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");

		    byte[] userSeed = new byte[256];

		    SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		    random.setSeed(userSeed);
		    //initialisation concerne la taille de la clé et une solution pour générer des nombres aléatoires
		    keyGen.initialize(1024, random);
		    
		    KeyPair keypair = keyGen.genKeyPair();
		    PrivateKey privateKey = keypair.getPrivate();
		    System.out.println("----------privateKey--------");
		    System.out.println(privateKey);
		    
		    System.out.println("----------publicKey---------");
		    PublicKey publicKey = keypair.getPublic();
		    System.out.println(publicKey);
		  
		  
	  }
	  
	  private  static void testKeyFactory() throws NoSuchAlgorithmException, InvalidKeySpecException{
		  //La classe KeyFactory permet de convertir des clés transparentes en clés opaques et vice versa.
		    // Generation d'une paire de cles opaques pour RSA

	      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	      keyGen.initialize(1024);
	      KeyPair keypair = keyGen.genKeyPair();
	      
	      System.out.println("----------publicKey---------");
	      PublicKey publicKey = keypair.getPublic();
	      System.out.println(ConvertionHelper.bytesToHex(publicKey.getEncoded()));
	      
	      System.out.println("----------privateKey--------");
	      PrivateKey privateKey = keypair.getPrivate();
	      System.out.println(ConvertionHelper.bytesToHex(privateKey.getEncoded()));
	      
	   // Convertion de la cle opaque en cle transparente

	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      byte[] publicKeyBytes = publicKey.getEncoded();
	      EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

	      byte[] privateKeyBytes = privateKey.getEncoded();
	      EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
	      
	      // Reconvertion de la cle transparente en cle opaque

	      System.out.println("----------Reconvertion--------");
	      //PublicKey generatePublic(KeySpec keySpec)
	      PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);
	      System.out.println("\n"+ConvertionHelper.bytesToHex(publicKey2.getEncoded()));
		  
	   // Convertion de la cle opaque en cle transparente par KeySpec getKeySpec(Key key, Class keySpec)
	      KeyFactory kfactory = KeyFactory.getInstance("RSA");
	      RSAPublicKeySpec keySpec = kfactory.getKeySpec(publicKey,RSAPublicKeySpec.class);
		  
	      // PrivateKey generatePrivate(KeySpec keySpec)
	      PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);
	      System.out.println("\n"+ConvertionHelper.bytesToHex(privateKey2.getEncoded()));
	  }
	  
	  private  static void testCertificateFactory(){
		  
//		  La classe CertificateFactory est une fabrique pour générer des certificats et des CRL (Certificate Revocation List).
//
//		  La classe permet d'obtenir une instance de type java.security.cert.X509Certificate pour un certificat X.509.
//
//		  La classe permet d'obtenir une instance de type java.security.cert.X509CRL pour un CRL.
		  
		  
		  FileInputStream in = null;

		    try {
		    	//permet d'obtenir une instance de type CertificateFactory
		      CertificateFactory cf = CertificateFactory.getInstance("X.509");
		      in = new FileInputStream("C:/java/moncertificat.cer");
		      //Pour générer une instance de type Certificate,
		      Certificate cert = cf.generateCertificate(in);
		      System.out.println(cert);
		    } catch (Exception e) {
		      e.printStackTrace();
		    } finally {
		      try {
		        in.close();
		      } catch (IOException e) {
		        e.printStackTrace();
		      }
		    }
   }
	  
	  private  static void testKeyGenerator(){
		  // L'API JCE (Java Cryptography Extension) est une extension de JCA qui lui ajoute des API pour l'encryptage et le décryptage, la génération de clés et l'authentification de messages avec des algorithmes de type MAC.
		 // La classe javax.crypto.KeyGenerator, fournie à partir de Java 1.4, permet de générer des clés utilisables par des algorithmes symétriques.
		  
		  KeyGenerator keyGen;
		    try {
		      keyGen = KeyGenerator.getInstance("DESede");

//		      public void init(int keysize); --> la taille de la clé (keysize)
//		      public void init(SecureRandom random);  --> nombres aléatoires sous la forme d'un objet de type SecureRandom
//		      public void init(int keysize, SecureRandom random);
//		      public void init(AlgorithmParameterSpec params);
//		      public void init(AlgorithmParameterSpec params, SecureRandom random);
		      keyGen.init(168);
		      //SecretKey: Interface qui définit les fonctionnalités d'une clé secrète
		      SecretKey cle = keyGen.generateKey();
		      System.out.println("cle (" + cle.getAlgorithm() + "," + cle.getFormat()
		          + ") : " + new String(cle.getEncoded()));
		      
		    //initialisation avec une instance de type SecureRandom.
		      keyGen = KeyGenerator.getInstance("DES");
		      keyGen.init(new SecureRandom());
		      SecretKey cle2 = keyGen.generateKey();
		      System.out.println("cle (" + cle2.getAlgorithm() + "," + cle2.getFormat()
		          + ") : " + new String(cle2.getEncoded()));
		      
		      //initialisation avec la taille de la clé et une instance de type SecureRandom.
		      keyGen = KeyGenerator.getInstance("DES");
		      keyGen.init(56, new SecureRandom());
		      SecretKey cle3 = keyGen.generateKey();
		      System.out.println("cle (" + cle3.getAlgorithm() + "," + cle3.getFormat()
		          + ") : " + new String(cle3.getEncoded()));
		      
		      // le KeyGenerator n'est pas initialisé
		      keyGen = KeyGenerator.getInstance("DES");
		      SecretKey cle4 = keyGen.generateKey();
		      System.out.println("cle (" + cle4.getAlgorithm() + "," + cle4.getFormat()
		          + ") : " + new String(cle4.getEncoded()));
		      
		      // La classe KeyGenerator est utilisable pour les différents algorithmes proposés par les implémentations du ou des fournisseurs enregistrées.
		      
		      System.out.println("Generation d'une cle pour DES");
		      keyGen = KeyGenerator.getInstance("DES");
		      SecretKey key = keyGen.generateKey();
		      System.out
		          .println("cle=" + ConvertionHelper.bytesToHex(key.getEncoded()));

		      System.out.println("Generation d'une cle pour Blowfish");
		      keyGen = KeyGenerator.getInstance("Blowfish");
		      key = keyGen.generateKey();
		      System.out
		          .println("cle=" + ConvertionHelper.bytesToHex(key.getEncoded()));

		      System.out.println("Generation d'une cle pour Triple DES");
		      keyGen = KeyGenerator.getInstance("DESede");
		      key = keyGen.generateKey();
		      System.out
		          .println("cle=" + ConvertionHelper.bytesToHex(key.getEncoded()));

		      System.out.println("Generation d'une cle pour AES");
		      keyGen = KeyGenerator.getInstance("AES");
		      key = keyGen.generateKey();
		      System.out
		          .println("cle=" + ConvertionHelper.bytesToHex(key.getEncoded()));
		      
		      
		    } catch (Exception e) {
		      e.printStackTrace();
		    }
		  
		  
	  }
	  
	  private  static void testSecretKeyFactory(){
		  
		  // La classe javax.crypto.SecretKeyFactory, ajoutée à Java 1.4, est une fabrique qui permet de convertir des clés opaques (instance de type java.security.Key) en clés transparentes (de type KeySpec) et vice versa.
//		  
//		  Une clé opaque (java.security.Key et ses classes filles java.security.PublicKey, java.security.PrivateKey et javax.crypto.SecretKey) ne permet pas de connaitre son implémentation.
//
//		  A la différence de la classe KeyFactory qui est utilisable avec des paires de clés publiques et privées, la classe SecretFactory n'est utilisable qu'avec des clés privées pour algorithmes symétriques.
	  
		  byte[] desKeyData = { (byte) 0x04, (byte) 0x01, (byte) 0x07, (byte) 0x04,
			        (byte) 0x02, (byte) 0x08, (byte) 0x02, (byte) 0x01 };
			    DESKeySpec desKeySpec;
			    try {
			      desKeySpec = new DESKeySpec(desKeyData);
			      
			      // La méthode static getInstance() permet d'obtenir une instance de type SecretFactory.
			      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			      
			      // La méthode SecretKey generateSecret(KeySpec keySpec) permet d'obtenir une clé opaque correspondant à la clé transparente fournie en paramètre
			      SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
			      
			      System.out.println("cle secrete : "
			          + ConvertionHelper.bytesToHex(secretKey.getEncoded()));
			      
			      System.out.println("algorithme  : " + secretKey.getAlgorithm());
			      
			      System.out.println("format      : " + secretKey.getFormat());
			      
			    } catch (InvalidKeyException e) {
			      e.printStackTrace();
			    } catch (NoSuchAlgorithmException e) {
			      e.printStackTrace();
			    } catch (InvalidKeySpecException e) {
			      e.printStackTrace();
			    }
	  }
	  
	  private  static void testCipher(){
		  
		  final String message = "Mon message a traiter";

		    KeyGenerator keyGen;
		    try {
		      keyGen = KeyGenerator.getInstance("DESede");
		      keyGen.init(168);
		      SecretKey cle = keyGen.generateKey();
		      System.out.println("cle : " + new String(cle.getEncoded()));

		      byte[] enc = encrypter(message, cle);
		      System.out.println("texte encrypte : " + new String(enc));

		      String dec = decrypter(enc, cle);
		      System.out.println("texte decrypte : " + dec);

		    } catch (Exception e) {
		      e.printStackTrace();
		    }
		  
		  
	  }
	  
	  public static byte[] encrypter(final String message, SecretKey cle)
		      throws NoSuchAlgorithmException, NoSuchPaddingException,
		      InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

//		    public static Cipher getInstance(String transformation);
//		    public static Cipher getInstance(String transformation, String provider);
//		    public static Cipher getInstance(String transformation, Provider provider);
//
//		    Le nom de la transformation peut prendre plusieurs formes :
//
//		        Algorithme_de_chiffrement
//		        Algorithme_de_chiffrement/mode/padding_scheme
//
//		     Le mode permet de préciser comment les données vont être chiffrées

//			    CBC : Cipher Block Chaining (défini dans le FIPS PUB 81)
//			    CFB, CFBn : Cipher FeedBack (défini dans le FIPS PUB 81). n est la taille optionnelle en bits du bloc
//			    CTR : version simplifiée du mode OFB
//			    CTS : Cipher Text Stealing
//			    ECB : Electronic CookBook (défini dans le FIPS PUB 81)
//			    NONE : aucun mode
//			    OFB, OFBn : Output FeedBack (défini dans FIPS PUB 81). n est la taille optionnelle en bits du bloc
//			    PCBC : Propagating Cipher Block Chaining (défini dans Kerberos V4)

//		     Le padding permet de préciser comment sera rempli le dernier bloc de données à chiffrer.
//		
//				    NoPadding : pas de padding
//				    ISO10126Padding : défini par le W3C dans le document "XML Encryption Syntax and Processing"
//				    OAEPPadding
//				    OAEPWith<digest>And<mgf>Padding : Optimal Asymmetric Encryption Padding avec digest qui est le nom de l'algorithme de type message digest
//				    PKCS1Padding : PKCS#1
//				    PKCS5Padding : PKCS#5 défini par les laboratoires RSA en 1993
//				    SSL3Padding : défini par le protocole SSL version 3.0


		    Cipher cipher = Cipher.getInstance("DESede");
		  

//		    public void init(int opmode, Key key)
//		    public void init(int opmode, Certificate certificate)
//		    public void init(int opmode, Key key, SecureRandom random)
//		    public void init(int opmode, Certificate certificate, SecureRandom random)
//		    public void init(int opmode, Key key, AlgorithmParameterSpec params)
//		    public void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random);
//		    public void init(int opmode, Key key, AlgorithmParameters params)
//		    public void init(int opmode, Key key, AlgorithmParameters params, SecureRandom random)

		    // le mode d'utilisation de l'instance de la classe Cipher. 
//		    ENCRYPT_MODE : chiffrer des données
//		    DECRYPT_MODE : déchiffrer des données
//		    WRAP_MODE : chiffrer une clé pour permettre son échange de manière sécurisée
//		    UNWRAP_MODE : déchiffrer une clé reçue pour obtenir une instance de type java.security.Key

		    cipher.init(Cipher.ENCRYPT_MODE, cle);
		    
		    byte[] donnees = message.getBytes();

		    // Pour chiffrer ou déchiffrer des données en une seule fois, il faut utiliser une des surcharges de la méthode doFinal() :
		    return cipher.doFinal(donnees);
		  }

		  public static String decrypter(final byte[] donnees, SecretKey cle)
		      throws NoSuchAlgorithmException, NoSuchPaddingException,
		      InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			  
		    Cipher cipher = Cipher.getInstance("DESede");
		    
		    cipher.init(Cipher.DECRYPT_MODE, cle);

		    return new String(cipher.doFinal(donnees));
		  }
		  
		  private  static void testCipherWrap (){
			  
			  // La classe Cipher permet d'envelopper une clé pour permettre son transfert ou son stockage de manière sécurisé
			
			  
			  try {
			  // génération de la clé à envelopper

		      KeyGenerator generator = KeyGenerator.getInstance("AES");
		      generator.init(128);
		      SecretKey cleAEnvelopper = generator.generateKey();
		      System.out.println("cle          : "
		          + ConvertionHelper.bytesToHex(cleAEnvelopper.getEncoded()));

		      // wrap de la clé

		      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		      KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
		      KeyGen.init(128);
		      Key clePourChiffrer = KeyGen.generateKey();
		      
//		      Pour encrypter une clé, il faut initialiser l'objet Cipher avec le mode WRAP_MODE et invoquer la méthode wrap() en lui passant en paramètre un objet de type Key qui est la clé à traiter.
//
//		      public final byte[] wrap(Key key)

		      cipher.init(Cipher.WRAP_MODE, clePourChiffrer);
		      byte[] cleEnveloppee = cipher.wrap(cleAEnvelopper);
		      
		      System.out.println("cle wrapped  : "
		          + ConvertionHelper.bytesToHex(cleEnveloppee));

		      // unwrap de la clé

//		      Pour permettre d'extraire une clé d'une enveloppe, il est nécessaire d'avoir le nom de l'algorithme utilisé et le type de clé enveloppée.
//
//		      Il faut initialiser l'instance de type Cipher avec le mode UNWRAP_MODE et invoquer la méthode unwrap().
//
//		          public final Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType))

		      cipher.init(Cipher.UNWRAP_MODE, clePourChiffrer);
		      Key key = cipher.unwrap(cleEnveloppee, "AES", Cipher.SECRET_KEY);
		      
		      System.out.println("cle unwrapped: "
		          + ConvertionHelper.bytesToHex(key.getEncoded()));

		    } catch (Exception e) {
		      e.printStackTrace();
		    }
		  }
		  
		  private  static void testCipherGetParameters  (){
			  
//			  La plupart des algorithmes utilisent des clés binaires qui sont difficiles à retenir par des humains : il est plus facile de retenir des mots de passes composés de caractères alphanumériques. 
//			  C'est la raison pour laquelle le protocole Password Based Encryption (PBE) a été développé pour générer une clé binaire forte à partir d'un mot de passe et de plusieurs paramètres dépendants de l'implémentation (nombre aléatoire, nombre d'itérations, salt, ...).
//              L'utilisation de ces différents paramètres par l'algorithme de l'implémentation permet d'améliorer la génération aléatoire de la clé binaire.


			  final String TRANSFORMATION = "PBEWithMD5AndDES";

			  char[] motDePasse = { 'M', 'o', 't', 'D', 'e', 'P',
			      'a', 's', 's', 'e' };

			  byte[] salt = new byte[] { 0x7e, (byte) 0xe0,
			      0x41, (byte) 0xf9, 0x4e, (byte) 0xa0, 0x60, 0x02 };
			  
			  try {
				  // chiffrer
			      SecretKeyFactory kf = SecretKeyFactory.getInstance(TRANSFORMATION);
			      PBEKeySpec keySpec = new PBEKeySpec(motDePasse);
			      SecretKey key = kf.generateSecret(keySpec);
			      PBEParameterSpec params = new PBEParameterSpec(salt, 1000);

			     
			      Cipher cipherEnc = Cipher.getInstance(TRANSFORMATION);
			      cipherEnc.init(Cipher.ENCRYPT_MODE, key, params);

			      byte[] texteChiffre = cipherEnc.doFinal("mon message".getBytes());
			      System.out.println("texte chiffre="
			          + ConvertionHelper.bytesToHex(texteChiffre));

			      AlgorithmParameters algParams = cipherEnc.getParameters();
			      byte[] encodedAlgParams = algParams.getEncoded();
			      
			      // dechiffrer
			       
			      
			      AlgorithmParameters algParamsDec;
			      algParamsDec = AlgorithmParameters.getInstance(TRANSFORMATION);
			      algParamsDec.init(encodedAlgParams);

			      Cipher cipherDec = Cipher.getInstance(TRANSFORMATION);

			      cipherDec.init(Cipher.DECRYPT_MODE, key, algParamsDec);
			      byte[] texteClair = cipherDec.doFinal(texteChiffre);
			      
			      System.out.println(new String(texteClair));
			      

			    } catch (Exception e) {
			      e.printStackTrace();
			    }
			  
			  
		  }
		  
		  private  static void testCipherDES_AES(){
			  
			  try {
			      KeyGenerator keyGen = KeyGenerator.getInstance("DES");
			      SecretKey secretKey = keyGen.generateKey();
			      String message = "Mon message à chiffer";

			      utiliserCipher(secretKey, "DES", message);
			      utiliserCipher(secretKey, "DES/ECB/PKCS5Padding", message);
			      utiliserCipher(secretKey, "DES/CBC/PKCS5Padding", message);
			      utiliserCipher(secretKey, "DES/PCBC/PKCS5Padding", message);
			      utiliserCipher(secretKey, "DES/CFB/PKCS5Padding", message);
			      utiliserCipher(secretKey, "DES/OFB/PKCS5Padding", message);
			      
			      KeyGenerator keyGen2 = KeyGenerator.getInstance("AES");
			      keyGen2.init(128);
			      SecretKey secretKey2 = keyGen2.generateKey();

			      Cipher aesCipher = Cipher.getInstance("AES");
			      aesCipher.init(Cipher.ENCRYPT_MODE, secretKey2);
			      byte[] byteCipherText = aesCipher.doFinal("Mon message".getBytes());
			      System.out.println("AES ENCRYPT_MODE "+ConvertionHelper.bytesToHex(byteCipherText));

			      aesCipher.init(Cipher.DECRYPT_MODE, secretKey2, aesCipher.getParameters());
			      byte[] byteDecryptedText = aesCipher.doFinal(byteCipherText);
			      System.out.println("AES DECRYPT_MODE "+new String(byteDecryptedText));

			    } catch (Exception e) {
			      System.out.println("Erreur " + e);
			    }
			  
			  
		  }
		  
		  public static void utiliserCipher(SecretKey secretKey, String transformation,
			      String message) throws NoSuchAlgorithmException, NoSuchPaddingException,
			      InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			      InvalidAlgorithmParameterException {
			  
			    Cipher desCipher = Cipher.getInstance(transformation);
			    desCipher.init(Cipher.ENCRYPT_MODE, secretKey);		        
			    byte[] byteCipherText = desCipher.doFinal(message.getBytes());
			    System.out.println(ConvertionHelper.bytesToHex(byteCipherText));

			    desCipher.init(Cipher.DECRYPT_MODE, secretKey, desCipher.getParameters());
			    byte[] byteDecryptedText = desCipher.doFinal(byteCipherText);
			    System.out.println(new String(byteDecryptedText));
			  }
		  
		  private  static void testMac(){
			  try {
			   String resultat = calculerMAC("Mon message", "maCle", "HmacSHA256");
			      System.out.println("HmacSHA256 digest : " + resultat);

			      resultat = calculerMAC("Mon message", "maCle", "HmacMD5");
			      System.out.println("HmacMD5 digest : " + resultat);
			    } catch (NoSuchAlgorithmException e) {
			      e.printStackTrace();
			    } catch (UnsupportedEncodingException e) {
			      e.printStackTrace();
			    } catch (InvalidKeyException e) {
			      e.printStackTrace();
			    }
			  
			  
		  }
		  

		  public static String calculerMAC(String message, String cle, String algorithme)
		      throws UnsupportedEncodingException, NoSuchAlgorithmException,
		      InvalidKeyException {
		    String resultat;

		    SecretKey secretKey = new SecretKeySpec(cle.getBytes("UTF-8"), algorithme);
		    System.out.println("cle : " + ConvertionHelper.bytesToHex(secretKey.getEncoded()));

		    Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		    mac.init(secretKey);

		    byte[] b = message.getBytes("UTF-8");
		    byte[] digest = mac.doFinal(b);

		    resultat = ConvertionHelper.bytesToHex(digest);
		    return resultat;
		  }
				
		

}
