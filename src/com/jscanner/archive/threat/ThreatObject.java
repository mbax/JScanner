package com.jscanner.archive.threat;

import java.util.ArrayList;
import java.util.List;

/**
 * The representation of a threat object.
 * 
 * @author Desmond Jackson
 */
public abstract class ThreatObject extends Object implements ThreatImpl {
	
	/**
	 * A list of all threat objects.
	 */
	private List<Class<? extends ThreatObject>> threatObjects;
	
	/**
	 * The state of the the threat object.
	 */
	private boolean used;
	
	/**
	 * The text to be written to the console.
	 */
	private String reply;
	
	/**
	 * Creates the threat object representation.
	 */
	public ThreatObject() {
		super();
		threatObjects = new ArrayList<Class<? extends ThreatObject>>();
	}
	
	/**
	 * Sets the text to be written to the console.
	 * 
	 * @param reply The text to set.
	 */
	public void setReply(String reply) {
		this.reply = reply;
	}
	
	@Override
	public void setUsed() {
		used = true;
	}
	
	@Override
	public void addThreatObject(Class<? extends ThreatObject> threatObject) {
		threatObjects.add(threatObject);
	}
	
	@Override
	public List<Class<? extends ThreatObject>> getThreatObjects() {
		return threatObjects;
	}
	
	/**
	 * Gets the message that will appear in the graphical user interface.
	 * 
	 * @return The message that will appear in the graphical user interface.
	 */
	public String getReply() {
		return reply;
	}
	
	@Override
	public boolean isUsed() {
		return used;
	}
	
}
