package com.jscanner.archive.threat.impl;

import java.net.URLClassLoader;

import com.jscanner.archive.threat.ThreatClass;

/**
 * Represents the URLClassLoader class.
 * 
 * @author Desmond Jackson
 */
public class URLClassLoaderClass extends ThreatClass {

	public URLClassLoaderClass() {
		super(URLClassLoader.class);
	}

	@Override
	public void addThreatMethods() {
		addThreatMethod(ClassLoaderClassLoadClass.class);
	}

	@Override
	public String getReply() {
		return "Reading the code from another Java program that is located on a website or server!";
	}

}
