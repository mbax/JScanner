package com.jscanner.archive.threat.impl;

import java.lang.reflect.Method;

import com.jscanner.archive.threat.ThreatClass;
import com.jscanner.archive.threat.ThreatMethod;

/**
 * Represents the deleteOnExit method in the File class.
 * 
 * @author Desmond Jackson
 */
public class FileClassDeleteOnExit extends ThreatMethod {

	/**
	 * Creates an instance of the FileClassDeleteOnExit class.
	 * 
	 * @param owner The threatening class that this method is found in.
	 */
	public FileClassDeleteOnExit(ThreatClass owner) {
		super(owner);
	}

	@Override
	public Method getMethod() {
		return owner.getMethod("deleteOnExit");
	}

	@Override
	public String getReply() {
		return "One or more files get deleted when the scanned application(s) stops!";
	}

}
