package com.jscanner.archive.threat.impl;

import java.io.OutputStream;

import com.jscanner.archive.threat.ThreatClass;

/**
 * Represents the OutputStream class.
 * 
 * @author Desmond Jackson
 */
public class OutputStreamClass extends ThreatClass {

	/**
	 * Creates an instance of the OutputStreamClass class.
	 */
	public OutputStreamClass() {
		super(OutputStream.class);
	}

	@Override
	public void addThreatMethods() {
		addThreatMethod(OutputStreamClassWrite.class);
	}

	@Override
	public String getReply() {
		return "Creates one or more output streams so that it "
				+ "can write data to websites, files, and servers!";
	}

}
