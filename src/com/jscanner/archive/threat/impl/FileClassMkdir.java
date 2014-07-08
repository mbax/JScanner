package com.jscanner.archive.threat.impl;

import java.lang.reflect.Method;

import com.jscanner.archive.threat.ThreatClass;
import com.jscanner.archive.threat.ThreatMethod;

/**
 * Represents the mdir method in the File class.
 * 
 * @author Desmond Jackson
 */
public class FileClassMkdir extends ThreatMethod {

	/**
	 * Creates an instance of the FileClassMkdir class.
	 * 
	 * @param owner The threatening class that this method is found in.
	 */
	public FileClassMkdir(ThreatClass owner) {
		super(owner);
	}

	@Override
	public Method getMethod() {
		return owner.getMethod("mkdir");
	}

	@Override
	public String getReply() {
		return "One or more directories get created!";
	}

}
