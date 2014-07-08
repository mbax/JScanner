package com.jscanner.archive.threat.impl;

import java.io.FileReader;

import com.jscanner.archive.threat.ThreatClass;

/**
 * Represents the FileReader class.
 * 
 * @author Desmond Jackson
 */
public class FileReaderClass extends ThreatClass {

	/**
	 * Creates an instance of the FileReaderClass class.
	 */
	public FileReaderClass() {
		super(FileReader.class);
	}

	@Override
	public void addThreatMethods() {
		addThreatMethod(FileReaderClassRead.class);
	}

	@Override
	public String getReply() {
		return "Will scan data from files.";
	}

}
