package org.wildfly.sasl.test;

import static org.junit.Assert.*;

import org.junit.Test;
import org.wildfly.sasl.util.ByteStringBuilder;
import org.wildfly.sasl.util.StringPrep;

/**
 * Part of future StringPrepTest
 * 
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class StringPrepBugTest {
	
	@Test // successful
	public void testForbitPrivateUseNonProblematic3bytesChar() throws Exception {
		try{
			ByteStringBuilder b = new ByteStringBuilder();
			StringPrep.encode("\uDBB4\uDD23", b, 0); // surrogate pair of 0xFD123
			throw new Exception("Not throwed IllegalArgumentException!");
		}catch(IllegalArgumentException e){}
	}
	
	@Test // failing with StringIndexOutOfBoundsException
	public void testForbitPrivateUseProblematic3bytesChars() throws Exception {
		try{
			ByteStringBuilder b = new ByteStringBuilder();
			StringPrep.encode("\uDBB6\uDC00", b, 0); // surrogate pair of 0xFD800
			throw new Exception("Not throwed IllegalArgumentException!");
		}catch(IllegalArgumentException e){}
	}
	
	
	
	// ----------- advanced test - all private use characters --------------
	
	@Test
	public void testForbitPrivateUse() throws Exception {
		testForbitCharsRange(StringPrep.FORBID_PRIVATE_USE, (int)0xE000,(int)0xF8FF);
		testForbitCharsRange(StringPrep.FORBID_PRIVATE_USE, (int)0xF0000,(int)0xFFFFD);
		testForbitCharsRange(StringPrep.FORBID_PRIVATE_USE, (int)0x100000,(int)0x10FFFD);
	}
	
	private String codePointToString(int codePoint){
		ByteStringBuilder b = new ByteStringBuilder();
		b.appendUtf8Raw(codePoint);
		return new String(b.toArray());
	}
	
	private void testForbitChar(long profile, int codePoint) throws Exception {
		try{
			ByteStringBuilder b = new ByteStringBuilder();
			StringPrep.encode(codePointToString(codePoint), b, profile);
			throw new Exception("Not throwed IllegalArgumentException for "+codePoint+"!");
		}
		catch(IllegalArgumentException e){}
	}
	
	private void testForbitCharsRange(long profile, int from, int to) throws Exception{
		for(int i = (int)from; i <= to; i++){
			testForbitChar(profile, i);
		}
	}
	
}
