package com.jscanner.archive.threat.impl;

import java.io.FileWriter;

import com.jscanner.archive.threat.ThreatClass;

/**
 * Represents the FileWriter class.
 * 
 * @author Desmond Jackson
 */
public class FileWriterClass extends ThreatClass {

	/**
	 * Creates an instance of the FileWriterClass class.
	 */
	public FileWriterClass() {
		super(FileWriter.class);
	}

	@Override
	public void addThreatMethods() {
		addThreatMethod(FileWriterClassAppend.class);
		addThreatMethod(FileWriterClassWrite.class);
	}

	@Override
	public String getReply() {
		return "Tampers with the data of files!";
	}

}
