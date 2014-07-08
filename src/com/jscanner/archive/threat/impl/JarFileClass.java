package com.jscanner.archive.threat.impl;

import java.util.jar.JarFile;

import com.jscanner.archive.threat.ThreatClass;

/**
 * Represents the JarFile class.
 * 
 * @author Desmond Jackson
 */
public class JarFileClass extends ThreatClass {

	/**
	 * Creates an instance of the JarFileClass class.
	 */
	public JarFileClass() {
		super(JarFile.class);
	}

	@Override
	public void addThreatMethods() {}

	@Override
	public String getReply() {
		return "Interacts with one or more jar files!";
	}

}
