package com.jscanner.archive.threat.impl;

import java.io.DataOutputStream;

import com.jscanner.archive.threat.ThreatClass;

/**
 * Represents the DataOutputStream class.
 * 
 * @author Desmond Jackson
 */
public class DataOutputStreamClass extends ThreatClass {

	/**
	 * Creates an instance of the DataOutputStreamClass class.
	 */
	public DataOutputStreamClass() {
		super(DataOutputStream.class);
	}

	@Override
	public void addThreatMethods() {}

	@Override
	public String getReply() {
		return "Creates one or more data output streams"
				+ " so that it can write data to websites, files, and servers!";
	}

}