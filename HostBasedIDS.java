import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class HostBasedIDS
{
	private static ArrayList<String> originalFileLocations = new ArrayList<String>(); //[Directory\hurkanugur.txt]
	private static HashMap<String,byte[]> originalFileContents = new HashMap<String,byte[]>(); //[KEY: Directory\hurkanugur.txt], [VALUE: Plaintext Content]
	
	private static HashMap<String,String> backupFileLocations = new HashMap<String,String>(); //[KEY: Directory\hurkanugur.txt], [VALUE: Directory\$Directory\$hurkanugur.txt]
	private static HashMap<String,byte[]> backupFileContents = new HashMap<String,byte[]>(); //[KEY: Directory\$Directory\$hurkanugur.txt], [VALUE: Encrypted Content]
	
	private static String originalDirectoryLocation, backupDirectoryLocation;
	private static String secretKeyMACString;
	private static int userChoice;
	
	//AES256 ENCRYPTION & DECRYPTION CLASS
	public static class HukoAES256
	{
		private static SecretKey secretKey = null;
		private static IvParameterSpec initializationVector =  null;
		private static String hexadecimalStringSecretKey = null;
	    private static String hexadecimalStringInitializationVector = null;
	    
	    //ENCAPSULATIONS
	    //GET SECRET KEY
		public static SecretKey GetSecretKeyOfAES256()
		{
			return HukoAES256.secretKey;
		}
		//SET SECRET KEY
		public static void SetSecretKeyOfAES256(SecretKey secretKey)
		{
			HukoAES256.secretKey = secretKey;
		}
		//GET HEXADECIMAL STRING SECRET KEY
		public static String GetHexSecretKeyAES256()
		{
			return HukoAES256.hexadecimalStringSecretKey;
		}
		//SET HEXADECIMAL STRING SECRET KEY THEN GENERATE AES256 SECRET KEY
		public static void SetHexSecretKeyAES256(String secretKey) throws Exception
		{
			HukoAES256.hexadecimalStringSecretKey = secretKey;
			//GENERATES AES-256 SECRET KEY FROM HEXADECIMAL STRING 
			byte[] secretKeyByteArray = Base64.getDecoder().decode(ConvertHexadecimalStringToByteArray(HukoAES256.hexadecimalStringSecretKey)); 
			HukoAES256.secretKey = new SecretKeySpec(secretKeyByteArray, 0, secretKeyByteArray.length, "AES");
		}
		
		//INITIALIZATION VECTOR GENERATOR
		private static IvParameterSpec InitializationVectorGenerator() throws Exception
		{
		    byte[] iv = new byte[16];
		    new SecureRandom().nextBytes(iv);
		    hexadecimalStringInitializationVector = ConvertByteArrayToHexadecimalString(iv);
		    return new IvParameterSpec(iv);
		}
		
		//GET HEXADECIMAL STRING INITIALIZATION VECTOR
		public static String GetHexInitializationVector()
		{
			return HukoAES256.hexadecimalStringInitializationVector;
		}
		//SET HEXADECIMAL STRING INITIALIZATION VECTOR THEN GENERATE AES256 - CBC IV
		private static void SetHexInitializationVector(String initializationVector) throws Exception
		{
			HukoAES256.hexadecimalStringInitializationVector = initializationVector;
			byte[] generatedInitializationVector = ConvertHexadecimalStringToByteArray(HukoAES256.hexadecimalStringInitializationVector); 
			HukoAES256.initializationVector =  new IvParameterSpec(generatedInitializationVector);
		}
		
		//AES256 SECRET KEY GENERATOR (GENERATES AES-256 BIT KEY FROM THE MAC CODE)
		public static void GenerateAES256SecretKeyFromMACSecretKey(String MAC_SECRET_KEY)
		{
			try 
			{
			    final String SALT = "Hurkan Ugur CSE 439 Term Project";
			    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
				KeySpec keySpec = new PBEKeySpec(MAC_SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
				SecretKey secretKey = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
				
				//CREATE INITIALIZATION VECTOR
				try{initializationVector =  InitializationVectorGenerator();}
				catch(Exception e) {System.out.println("[Initialization Vector]: Something went wrong !"); throw new Exception();}
				//SAVE CALCULATED SECRET KEY
				HukoAES256.secretKey = secretKey;
			}
			catch(Exception e) 
			{
				System.out.println("[AES256 Secret Key Generator]: Something went wrong !");
			}
		}
		
		//AES-256 ENCRYPTION FUNCTION
		public static byte[] EncryptionWithAES256(byte[] Data)
		{
			try 
			{
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			    cipher.init(Cipher.ENCRYPT_MODE, HukoAES256.secretKey, initializationVector);
			    byte[] cipherText = cipher.doFinal(Data);
			    return Base64.getEncoder().encode(cipherText);
			}
			catch(Exception e)
			{
				System.out.println("[AES256 Encryption]: Something went wrong !");
				return null;
			}
		}

		//AES-256 DECRYPTION FUNCTION
		public static byte[] DecryptionWithAES256(String Data) throws Exception
		{ 
			try 
			{
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			    cipher.init(Cipher.DECRYPT_MODE, HukoAES256.secretKey, initializationVector);
			    byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(Data));
			    return plainText;
			}
			catch(Exception e) //IF THE EXCEPTION IS THROWN, HANDLE IT BOTH IN HERE AND THE PLACE WHERE IT IS CALLED
			{
				System.out.println("[AES256 Decryption]: Something went wrong !");
				//SEND AN EXCEPTION TO THE PLACE WHERE THIS FUNCTION IS CALLED
				throw new Exception();
			}
		}
	}

	//[FOR PART 1 & PART 2]: READ ORIGINAL DOCUMENTS AND STORE THEIR INFO IN ARRAYLISTS & HASHMAPS
	public static boolean ReadOriginals()
	{
		try 
		{
			//CREAR ALL PREVIOUS RECORDS
			if(userChoice == 0)
				HukoAES256.SetSecretKeyOfAES256(null);
			
			originalFileContents.clear();
			backupFileContents.clear();
			originalFileLocations.clear();
			backupFileLocations.clear();
			
			
			//GET DIRECTORY NAME TO BE SECURED
			File originalDirectory = new File(originalDirectoryLocation);
			backupDirectoryLocation = originalDirectoryLocation + "\\$" + originalDirectory.getName();
			
			try
			{
				//ELIMINATE DIRECTORIES, ONLY TAKE THE NAMES OF FILES
				String[] getDirectoriesAndFiles = originalDirectory.list();
				for(String fileName : getDirectoriesAndFiles)
				{
					File originalFileLocation = new File(originalDirectoryLocation + "\\" + fileName);
					if(!originalFileLocation.isDirectory()) 
					{
						originalFileLocations.add(originalFileLocation.getPath());
						backupFileLocations.put(originalFileLocation.getPath(), backupDirectoryLocation + "\\$" + fileName);
					}
				}
				
				if(originalFileLocations.size() == 0)
				{
					System.out.println("---------------------------------------------");
					if(userChoice == 0) //[PART 1]: CREATING BACKUP PHASE
						System.out.println("[Original File Reading]: There is no file to read in [" + originalDirectoryLocation + "] !"); 
					else if(userChoice == 1) //[PART 2]: CHECKING BACKUP PHASE
					{
						System.out.println("[Original File Reading]: Original Files are missing in [" + originalDirectoryLocation + "] !");
						System.out.println("[ALERT]: The System has been compromised !");
					}
					return false;
				}
				else
					System.out.println("[Original File Reading]: Files are being read..."); 
			}
			//IF THE ORIGINAL DIRECTORY DOES NOT EXIST, IT IF THROW AN EXCEPTION
			catch(Exception e) 
			{
				if(userChoice == 0) //FOR PART 1
					System.out.println("[Original File Reading]: There is no directory called [" + originalDirectoryLocation + "] !"); 
				else if(userChoice == 1) //FOR PART 2
				{
					System.out.println("[Original File Reading]: The Directory [" + originalDirectoryLocation + "] has been deleted !"); 
					System.out.println("[ALERT]: The System has been compromised !");
				}
				return false;
			}
			
			//READ AND STORE THE CONTENT OF ORIGINAL FILES IN THE DIRECTORY
			for(String originalFileLocation : originalFileLocations)
			{
				FileInputStream fileInputStream = new FileInputStream(originalFileLocation);
				DataInputStream dataInputStream = new DataInputStream(fileInputStream);
	
				//READ EACH FILE BYTE BY BYTE
				int data;
				ByteArrayOutputStream bAOS = new ByteArrayOutputStream();
				while((data = dataInputStream.read()) != -1)
					bAOS.write(data);
				
				//SAVE CONTENTS OF THE CORRESPONDING FILES
				originalFileContents.put(originalFileLocation, bAOS.toByteArray());
				bAOS.flush();
				bAOS.close();
				dataInputStream.close();
				fileInputStream.close();
			}
			if(originalFileLocations.size() != 0)
			{
				System.out.println("[Original File Reading]: " + originalFileLocations.size() + " file(s) are read successfully from [" + originalDirectoryLocation + "]");
				return true;
			}
			throw new Exception();
		}
		catch (Exception e) { System.out.println("[Original File Reading]: Something went wrong !"); return false;}
	}
	
	//[FOR PART 1]: STORE DOCUMENTS THAT ARE CONVERTED FROM ORIGINAL TO CIPHERTEXT
	public static boolean StoreBackup()
	{
		try 
		{
			File backupDirectory = new File(backupDirectoryLocation);
			backupDirectory.mkdir();
			System.out.println("[Backup File Writing]: Create Directory -> " + backupDirectory.getPath());
			System.out.println("[Backup File Writing]: Files are being stored..."); 
			for(String originalFileLocation : originalFileLocations)
			{
				String backupFileLocation = backupFileLocations.get(originalFileLocation);
				FileOutputStream fileOutputStream = new FileOutputStream(backupFileLocation);
				DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream); 
				byte byteArray[] = backupFileContents.get(backupFileLocation); 
				dataOutputStream.write(byteArray);
				dataOutputStream.flush();
				dataOutputStream.close();
				fileOutputStream.close();   
			}
			System.out.println("[Backup File Writing]: " + backupFileLocations.size() + " file(s) are stored successfully in [" + backupDirectoryLocation + "]");
			return true;
		}
		catch(Exception e){ System.out.println("[Backup File Writing]: Something went wrong !"); return false;}
	}
	
	//[FOR PART 2]: READ BACKUP FILES TO CHECK THEIR MAC CODES IN THE FUTURE
	public static boolean ReadBackup()
	{
		try
		{
			//CHECK IF BACKUP DIRECTORY IS DELETED OR NOT
			File backupDirectory = new File(backupDirectoryLocation);
			if(!backupDirectory.exists())
			{
				System.out.println("---------------------------------------------");
				System.out.println("[Backup Read File]: Backup directory [" + backupDirectoryLocation +"] has been deleted !");
				System.out.println("[ALERT]: The System has been compromised !");
				return false;
			}
			//CHECK IF BOTH ORIGINAL AND BACKUP DIRECTORIES CONTAINS THE SAME FILES
			//CHECK IF THERE IS A DELETED FILES OR MODIFIED FILE NAMES OR ADDITIONAL ILLEGAL FILES
			else
			{
				//GET ALL EXISTING BACKUP FILES IN BACKUP DIRECTORY (ELIMINATE DIRECTORIES)
				String[] getDirectoriesAndFiles = backupDirectory.list();
				ArrayList<String> existingBackupFileLocations = new ArrayList<String>();
				for(String fileName : getDirectoriesAndFiles)
				{
					File backupFileLocation = new File(backupDirectoryLocation + "\\" + fileName);
					if(!backupFileLocation.isDirectory()) 
						existingBackupFileLocations.add(backupFileLocation.getPath());
				}
				//CHECK IF EXISTING FILES ARE THE SAME AS EXPECTED FILES (DETERMINED IN ORIGINAL FILE READING FUNCTION)
				ArrayList<String> expectedBackupFileLocations = new ArrayList<String>(backupFileLocations.values());
				Collections.sort(existingBackupFileLocations);
				Collections.sort(expectedBackupFileLocations);
				if(!existingBackupFileLocations.equals(expectedBackupFileLocations))
				{
					System.out.println("---------------------------------------------");
					System.out.println("[Backup File Reading]: The Directories [" + originalDirectoryLocation + "] and [" + backupDirectoryLocation + "] are modified !");
					System.out.println("[ALERT]: The System has been compromised !");
					return false;
				}
			}

			//READ BACKUP FILES ONE BY ONE
			for(String originalFileLocation : originalFileLocations)
			{	
				if(!new File(backupFileLocations.get(originalFileLocation)).exists())
					continue;
				
				FileInputStream fileInputStream = new FileInputStream(backupFileLocations.get(originalFileLocation));
				DataInputStream dataInputStream = new DataInputStream(fileInputStream);
				//READ EACH FILE BYTE BY BYTE
				int data;
				ByteArrayOutputStream bAOS = new ByteArrayOutputStream();
				while((data = dataInputStream.read()) != -1)
					bAOS.write(data);
				
				//SAVE CONTENTS OF THE CORRESPONDING FILES
				backupFileContents.put(backupFileLocations.get(originalFileLocation), bAOS.toByteArray());
				bAOS.flush();
				bAOS.close();
				dataInputStream.close();
				fileInputStream.close();
			}
			System.out.println("[Backup File Reading]: " + backupFileContents.size() + " file(s) are read successfully from [" + backupDirectoryLocation + "]");
			return true;
		}
		catch(Exception e) {System.out.println("[Backup File Reading]: Something went wrong !"); return false;}
	}
	
	//CONVERT BYTE[] -> HEX VALUE STRING
	public static String ConvertByteArrayToHexadecimalString(byte[] byteArray) 
	{
		final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(Charset.defaultCharset());
	    byte[] HEX_VALUE = new byte[byteArray.length * 2];
	    int i;
	    for (i = 0; i < byteArray.length; i++) {
	        int v = byteArray[i] & 0xFF;
	        HEX_VALUE[i * 2] = HEX_ARRAY[v >>> 4];
	        HEX_VALUE[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(HEX_VALUE, 0, HEX_VALUE.length);
	}
	
	//CONVERT HEX VALUE STRING -> BYTE[]
	public static byte[] ConvertHexadecimalStringToByteArray(String hexadecimalString) 
	{
	    int len = hexadecimalString.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) 
	    {
	        data[i / 2] = (byte) ((Character.digit(hexadecimalString.charAt(i), 16) << 4)
	                             + Character.digit(hexadecimalString.charAt(i+1), 16));
	    }
	    return data;
	}
	
	//[FOR PART 1]: CREATE SECRET KEY FOR MAC OPERATION
	public static SecretKey SecretKeyGenerator()
	{
		try 
		{
			KeyGenerator keygen = KeyGenerator.getInstance("AES"); //DETERMINE CRYPTO ALGORITHM TO BE USED
			keygen.init(256, SecureRandom.getInstanceStrong()); //SECRET KEY LENGTH
			SecretKey secretKey = keygen.generateKey(); //CREATE SECRET KEY
			return secretKey;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("[Secret Key Generator]: Something went wrong !");
			return null;
		}
	}
	
	//[FOR PART 1]: CREATE MAC AND STORE THEM BY ADDING THEM AT THE END OF THE FILE ALONG WITH SECRETKEY
	public static boolean CreateMessageAuthenticationCode()
	{
		try 
		{
			SecretKey secretKey = SecretKeyGenerator();
			if(secretKey != null)
			{
				for(String originalFileLocation: originalFileLocations)
				{
					Mac mac = Mac.getInstance("HmacSHA512");
					mac.init(new SecretKeySpec(secretKey.getEncoded(), "AES")); //INITIALIZE MAC WITH SYMMETRIC KEY
					mac.update(originalFileContents.get(originalFileLocation)); //ADD ORIGINAL DATA TO MAC OBJECT TO CALCULATE MAC
					//ADD MAC AND SECRET KEY AT THE END OF EACH FILE:
					//\n[MAC]: MAC CODE
					ByteArrayOutputStream bAOS = new ByteArrayOutputStream();
					bAOS.write(originalFileContents.get(originalFileLocation));
					bAOS.write("\n[MAC]:".getBytes());
					bAOS.write(mac.doFinal()); // CALCULATE MAC VALUE
					
					//PUT ALL PLAINTEXT DATA IN A BYTE[]
					byte[] plaintextData = bAOS.toByteArray();
					//GENERATE AES256 SECRET KEY BY USING MAC SECRET KEY
					if(HukoAES256.GetSecretKeyOfAES256() == null)
						HukoAES256.GenerateAES256SecretKeyFromMACSecretKey(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
					//ENCRYPT PLAINTEXT DATA WITH AES256
					byte[] ciphertextData = HukoAES256.EncryptionWithAES256(plaintextData);
					//SAVE THE ENCRYPTED CIPHERTEXT
					backupFileContents.put(backupFileLocations.get(originalFileLocation), ciphertextData);
				}
				//CONVERT SECRETKEY BYTE[] -> HEXADECIMAL STRING SECRETKEY (FOR BOTH MAC AND AES)
				secretKeyMACString = ConvertByteArrayToHexadecimalString(Base64.getEncoder().encode(secretKey.getEncoded()));
				HukoAES256.SetHexSecretKeyAES256(ConvertByteArrayToHexadecimalString(Base64.getEncoder().encode(HukoAES256.GetSecretKeyOfAES256().getEncoded())));
				return true;
			}
			throw new Exception();
		} catch (Exception e) {
			System.out.println("[Creating and Storing MAC]: Something went wrong !");
			return false;
		}
	}
	
	//[FOR PART 2]: COMPARE NEW MAC CODE AND OLD MAC CODE (NEW MAC CODE IS CREATED BY OLD SECRET KEY OF EACH FILE)
	public static void ControlMessageAuthenticationCode()
	{
		try 
		{
			int SomethingHasBeenChanged = 0;
			for(String originalFileLocation: originalFileLocations)
			{
				//GET OLD BACKUP FILE (IT IS SAVED IN BYTE[] FORMAT)
				byte[] oldEncryptedInfoByteArray = backupFileContents.get(backupFileLocations.get(originalFileLocation));
				//CONVERT Encrypted BYTE[] -> Encrypted String
				String oldEncryptedInfoString = new String(oldEncryptedInfoByteArray, 0, oldEncryptedInfoByteArray.length, Charset.defaultCharset());
				
				//*********** <<<<AES256 DECRYPTION>>>>, THEN CONVERT BYTE[] -> STRING **********************
				byte[] oldDecryptedInfoByteArray = null;
				String oldDecryptedInfoString = null;
				try 
				{
					oldDecryptedInfoByteArray = HukoAES256.DecryptionWithAES256(oldEncryptedInfoString);
					oldDecryptedInfoString = new String(oldDecryptedInfoByteArray, 0, oldDecryptedInfoByteArray.length, Charset.defaultCharset());
				}
				catch(Exception e)
				{
					SomethingHasBeenChanged = 1;
					System.out.println("[DECRYPTION ALERT]: This file is compromised -> " + originalFileLocation);
					continue;
				}
				
				//IF THE MAC LINE IS DELETED IN THE BACKUP FILE, THIS WILL THROW AN EXCEPTION
				String oldPlaintextInfoString;
				String oldMACValue;
				try 
				{
					//GET OLD ORIGINAL PART THEN SAVE IT (ORIGINAL PART CORRESPONDS THE PART BEFORE "\n[MAC]:" LINE) 
					oldPlaintextInfoString = oldDecryptedInfoString.substring(0, oldDecryptedInfoString.indexOf("\n[MAC]:"));
					//GET OLD MAC VALUE PART THEN SAVE IT (THE PART AFTER "\n[MAC]:", UNTIL END OF THE FILE")
					oldMACValue = oldDecryptedInfoString.substring(oldDecryptedInfoString.indexOf("\n[MAC]:") + 7);
				}
				catch(Exception e)
				{
					SomethingHasBeenChanged = 1;
					System.out.println("[ALERT]: This file is compromised -> " + originalFileLocation);
					continue;
				}

				//CONVERT HEXADECIMAL STRING SECRETKEY  -> BYTE[] SECRETKEY (IF THE SECRETKEY IS NOT A REAL KEY, IT WILL THROW AN EXCEPTION)
				//THEN WE REGENERATE OUR OLD SECRET KEY OFFICIALLY ! (9 LINES BELOW)
				byte[] secretKeyByteArray = null;
				try {secretKeyByteArray = Base64.getDecoder().decode(ConvertHexadecimalStringToByteArray(secretKeyMACString));} 
				catch(Exception e)
				{
					SomethingHasBeenChanged = 1;
					System.out.println("[ALERT]: MAC Secret Key is not valid !");
					return;
				}
				SecretKey regeneratedSecretKey = new SecretKeySpec(secretKeyByteArray, 0, secretKeyByteArray.length, "AES");
				
				//TO CREATE MAC CODE OF THE NEW FILE, USE THE OLD SECRET KEY 
				Mac mac = Mac.getInstance("HmacSHA512");
				mac.init(new SecretKeySpec(regeneratedSecretKey.getEncoded(),"AES")); //INITIALIZE MAC WITH SYMMETRIC KEY
				mac.update(originalFileContents.get(originalFileLocation)); //ADD ORIGINAL DATA TO MAC OBJECT TO CALCULATE MAC
				//NEW MAC CODE IS CREATED AND SAVED AS STRING (ACTUAL VALUE IS BYTE[])
				String newMACValue = new String(mac.doFinal(), Charset.defaultCharset());
				//SAVE NEW ORIGINAL FILE AS STRING
				String newPlaintextInfoString = new String(originalFileContents.get(originalFileLocation), 0, originalFileContents.get(originalFileLocation).length, Charset.defaultCharset());
				
				//IF OLD MAC VALUE != NEW MAC VALUE, THAT MEANS SYSTEM IS COMPROMISED !!!
				if(!newMACValue.equals(oldMACValue) || !newPlaintextInfoString.equals(oldPlaintextInfoString)) 
				{
					SomethingHasBeenChanged = 1;
					System.out.println("[ALERT]: This file is compromised -> " + originalFileLocation);
				}
			}
			if(SomethingHasBeenChanged == 0)
				System.out.println("[Scanning Result]: Everything is OK !");
			
		} catch (Exception e) {
			System.out.println("[Controling MAC]: Something went wrong !");
		}
	}
	public static void main(String[] args) 
	{
		Security.setProperty("crypto.policy", "unlimited");
		Scanner hukoScanner = new Scanner(System.in);
		userChoice = 0;
		while(userChoice != 2)
		{
			System.out.println("---------------------------------------------");
			System.out.println("[0]: Create backup of a Directory\n[1]: Check if there is an Intrusion\n[2]: Exit");
			System.out.println("---------------------------------------------");
			System.out.print("[Your Choice]: ");
			try{userChoice = hukoScanner.nextInt(); hukoScanner.nextLine();}catch(Exception e) { userChoice = -1; hukoScanner.nextLine();}
			switch (userChoice) 
			{
			case 0:
				//PART1
				System.out.println("---------------------------------------------");
				System.out.print("Enter the Directory name to be scanned: ");
				originalDirectoryLocation = hukoScanner.nextLine();
				
				if(ReadOriginals() == true)
					if(CreateMessageAuthenticationCode() == true)
						if(StoreBackup() == true)
						{
							System.out.println("---------------------------------------------");
							System.out.println("[Decryption Secret Key]: " + HukoAES256.GetHexSecretKeyAES256());
							System.out.println("[Initialization Vector]: " + HukoAES256.GetHexInitializationVector());
							System.out.println("[MAC Secret Key]: " + secretKeyMACString);
						}
				break;
			case 1:
				//PART2
				System.out.println("---------------------------------------------");
				System.out.print("Enter the Directory name to be scanned: ");
				originalDirectoryLocation = hukoScanner.nextLine();
				if(new File(originalDirectoryLocation).exists())
				{
					//GET DECRYPTION SECRET KEY
					try {System.out.print("Enter Decryption Secret Key: ");HukoAES256.SetHexSecretKeyAES256(hukoScanner.nextLine());} 
					catch (Exception e) {System.out.println("[ALERT]: Decryption Secret Key is not valid !"); break;}
					//GET INITIALIZATION VECTOR
					try {System.out.print("Enter Initialization Vector: ");HukoAES256.SetHexInitializationVector(hukoScanner.nextLine());} 
					catch (Exception e) {System.out.println("[ALERT]: Initialization Vector is not valid !"); break;}
					//GET MAC SECRET KEY
					System.out.print("Enter MAC Secret Key: ");
					secretKeyMACString = hukoScanner.nextLine();
					if(secretKeyMACString.length() != 88 || HukoAES256.GetHexSecretKeyAES256().length() != 88 || HukoAES256.GetHexInitializationVector().length() != 32)
					{
						System.out.println("---------------------------------------------");
						System.out.println("[ALERT]: One of the Key is not valid !");
						break;
					}
				}
				if(ReadOriginals() == true) 
					if(ReadBackup() == true)
					{
						System.out.println("---------------------------------------------");
						ControlMessageAuthenticationCode();
					}
				break;
			case 2:
				System.out.println("---------------------------------------------");
				break;
			default:
				System.out.println("[Input]: There is no such option !");
				break;
			}
		}
		hukoScanner.close();
		System.out.println(":::::::::::::::::::CSE:439:::::::::::::::::::");
		System.out.println("::::::HURKAN::UGUR::::SECURITY::PROJECT::::::");
	}
}
