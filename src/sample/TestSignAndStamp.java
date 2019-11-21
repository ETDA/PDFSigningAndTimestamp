package sample;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SignatureException;

import main.SignAndTimeStamp;

public class TestSignAndStamp {
	public static void main(String[] args) throws SignatureException, IOException, GeneralSecurityException {

		
		/**** Sample Input ****/
		String passwordP12 = "123456";
		String inputFileP12 = "itsaya.p12";
		String inputFileName = "pdfA3.pdf";
		String outputFile = "tsa_signed.pdf";
		String filePath = "resources/";
		String tsaUrl = "";
		String keystorePath = "";
		String keystorePassword = "";
		String keystoreType = "PKCS12";
		
		
//		String passwordP12 = args[0];
//		String inputFileP12 = args[1];
//		String inputFileName = args[2];
//		String outputFile = args[3];
//		String filePath = args[4];
//		String tsaUrl = args[5];
//		String keystorePath = args[6];
//		String keystorePassword = args[7];
//		String keystoreType = args[8];

		
		SignAndTimeStamp.signWithTSA(passwordP12, inputFileP12, inputFileName, outputFile, 
									filePath, tsaUrl, keystorePath, keystorePassword,keystoreType);
		

		System.out.println("********Sign And TimeStamp Done**********");
	}

}