package com.cryptography.jca;

public class ConvertionHelper {
	
	  public static String bytesToHex(byte[] b) {
		    char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
		        'B', 'C', 'D', 'E', 'F' };
		    StringBuffer buffer = new StringBuffer();
		    for (int j = 0; j < b.length; j++) {
		      buffer.append(hexDigits[(b[j] >> 4) & 0x0f]);
		      buffer.append(hexDigits[b[j] & 0x0f]);
		    }
		    return buffer.toString();
		  }

}
