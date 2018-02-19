package sample;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SignatureException;

import main.SignAndTimeStamp;

public class TestSignAndStamp {
	public static void main(String[] args) throws SignatureException, IOException, GeneralSecurityException {

		
		/**** Sample Input ****/
		/*String passwordP12 = "123456789";
		String inputFileP12 = "key.p12";
		String inputFileName = "pdfA3.pdf";
		String outputFile = "tsa_signed.pdf";
		String filePath = "resources/";
		String urlTsaClient = "http://test.time.teda.th";
		String userTsaClient = "";
		String passwordTsaClient = "";
		*/
		
		String passwordP12 = args[0];
		String inputFileP12 = args[1];
		String inputFileName = args[2];
		String outputFile = args[3];
		String filePath = args[4];
		String urlTsaClient = args[5];
		String userTsaClient = args[6];
		String passwordTsaClient = args[7];
		SignAndTimeStamp.signWithTSA(passwordP12, inputFileP12, inputFileName, outputFile, filePath, urlTsaClient, userTsaClient, passwordTsaClient);

		System.out.println("********Sign And TimeStamp Done**********");
	}

}
