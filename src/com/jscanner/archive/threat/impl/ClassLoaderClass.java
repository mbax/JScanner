package com.jscanner.archive.threat.impl;

import com.jscanner.archive.threat.ThreatClass;

/**
 * Represents the ClassLoader class.
 * 
 * @author Desmond Jackson
 */
public class ClassLoaderClass extends ThreatClass {

	/**
	 * Creates an instance of the ClassLoaderClass class.
	 */
	public ClassLoaderClass() {
		super(ClassLoader.class);
	}

	@Override
	public void addThreatMethods() {
		addThreatMethod(ClassLoaderClassLoadClass.class);
	}

	@Override
	public String getReply() {
		return "Reading the code of another Java program for later use!";
	}

}
