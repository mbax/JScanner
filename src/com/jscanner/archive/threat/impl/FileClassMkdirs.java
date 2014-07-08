package com.jscanner.archive.threat.impl;

import java.lang.reflect.Method;

import com.jscanner.archive.threat.ThreatClass;
import com.jscanner.archive.threat.ThreatMethod;

/**
 * Represents the mkdirs method in the File class.
 * 
 * @author Desmond Jackson
 */
public class FileClassMkdirs extends ThreatMethod {

	/**
	 * Creates an instance of the FileClassMkdirs class.
	 * 
	 * @param owner The threatening class that this method is found in.
	 */
	public FileClassMkdirs(ThreatClass owner) {
		super(owner);
	}

	@Override
	public Method getMethod() {
		return owner.getMethod("mkdirs");
	}

	@Override
	public String getReply() {
		return "Multiple directories get created simultaneously!";
	}

}
