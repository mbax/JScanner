package com.jscanner.archive;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.jscanner.JScanner;
import com.jscanner.archive.threat.ThreatClass;
import com.jscanner.archive.threat.ThreatMethod;
import com.jscanner.archive.threat.impl.CipherClass;
import com.jscanner.archive.threat.impl.ClassLoaderClass;
import com.jscanner.archive.threat.impl.DataInputStreamClass;
import com.jscanner.archive.threat.impl.DataOutputStreamClass;
import com.jscanner.archive.threat.impl.DatagramSocketClass;
import com.jscanner.archive.threat.impl.FileClass;
import com.jscanner.archive.threat.impl.FileReaderClass;
import com.jscanner.archive.threat.impl.FileWriterClass;
import com.jscanner.archive.threat.impl.InputStreamClass;
import com.jscanner.archive.threat.impl.JarFileClass;
import com.jscanner.archive.threat.impl.OutputStreamClass;
import com.jscanner.archive.threat.impl.RuntimeClass;
import com.jscanner.archive.threat.impl.ServerSocketClass;
import com.jscanner.archive.threat.impl.SocketClass;
import com.jscanner.archive.threat.impl.URLClass;
import com.jscanner.archive.threat.impl.URLClassLoaderClass;

/**
 * Scans a user selected archive for threats.
 * 
 * @author Desmond Jackson
 */
public class ArchiveScanner extends Object implements Opcodes {

	/**
	 * The threats selected in the "Plugins" graphical user interface.
	 */
	public static Map<String, Boolean> pluginThreats =
			new TreeMap<String, Boolean>();

	/**
	 * The archive to scan.
	 */
	private Archive archive;

	/**
	 * A list of all the threatening classes.
	 */
	private List<Class<? extends ThreatClass>> threatClasses;

	/**
	 * Prepares the archive to be scanned.
	 * 
	 * @param archive The archive to scan.
	 */
	public ArchiveScanner(Archive archive) {
		super();
		this.archive = archive;
		this.threatClasses = new ArrayList<Class<? extends ThreatClass>>();
		loadThreatClasses();
		scan();
	}

	/**
	 * Loads all threatening classes into memory.
	 */
	private void loadThreatClasses() {
		threatClasses.add(CipherClass.class);
		threatClasses.add(ClassLoaderClass.class);
		threatClasses.add(DatagramSocketClass.class);
		threatClasses.add(DataInputStreamClass.class);
		threatClasses.add(DataOutputStreamClass.class);
		threatClasses.add(FileClass.class);
		threatClasses.add(FileReaderClass.class);
		threatClasses.add(FileWriterClass.class);
		threatClasses.add(InputStreamClass.class);
		threatClasses.add(JarFileClass.class);
		threatClasses.add(OutputStreamClass.class);
		threatClasses.add(RuntimeClass.class);
		threatClasses.add(ServerSocketClass.class);
		threatClasses.add(SocketClass.class);
		threatClasses.add(URLClass.class);
		threatClasses.add(URLClassLoaderClass.class);
	}

	/**
	 * Scans the archive for threats.
	 */
	private void scan() {
		JScanner.log("Scanning: " + archive.getName());
		JScanner.log("Time: " + new Date(System.currentTimeMillis()) + "\n");
		Map<ThreatClass, List<ThreatMethod>> threatMap = getThreatMap();
		for (ClassNode classNode : archive)
			for (Object object : classNode.methods)
				if (object instanceof MethodNode) {
					MethodNode methodNode = (MethodNode) object;
					for (AbstractInsnNode abstractInsnNode : methodNode.instructions.toArray())
						if (abstractInsnNode instanceof MethodInsnNode) {
							MethodInsnNode methodInsnNode = (MethodInsnNode) abstractInsnNode;
							String methodInsnNodeOwner = "L" + methodInsnNode.owner + ";";
							for (Entry<ThreatClass, List<ThreatMethod>> threatEntry : threatMap.entrySet()) {
								ThreatClass threatClassInstance = threatEntry.getKey();
								if (methodInsnNodeOwner.equals(threatClassInstance.getName())) {
									threatClassInstance.setUsed();
									for (ThreatMethod threatMethodInstance : threatEntry.getValue()) {
										if (methodInsnNode.name.equals(threatMethodInstance.getName()))
											threatMethodInstance.setUsed();
									}
								}
							}
							for (Entry<String, Boolean> entry : pluginThreats.entrySet()) {
								if (methodInsnNode.owner.equals(entry.getKey()))
									entry.setValue(true);
								if ((methodInsnNode.name + methodInsnNode.desc)
										.equals(entry.getKey()))
									entry.setValue(true);
							}

						}
				}
		boolean regularThreatsFound = false;
		for (Entry<ThreatClass, List<ThreatMethod>> threatEntry : threatMap.entrySet()) {
			ThreatClass threatClassInstance = threatEntry.getKey();
			if (threatClassInstance.isUsed()) {
				regularThreatsFound = true;
				JScanner.log(threatClassInstance.getReply());
				for (ThreatMethod threatMethodInstance : threatEntry.getValue())
					if (threatMethodInstance.isUsed())
						JScanner.log(threatMethodInstance.getReply());
				JScanner.log("\n");
			}
		}
		if (!regularThreatsFound)
			JScanner.log("No regular threats found in this archive!\n");
		boolean pluginThreatsFound = false;
		for (Entry<String, Boolean> pluginEntry : pluginThreats.entrySet())
			if (pluginEntry.getValue()) {
				pluginThreatsFound = true;
				JScanner.log(pluginEntry.getKey() + " is used.");
			}
		if (!pluginThreatsFound)
			JScanner.log("No plugin threats found in this archive!\n");
	}

	/**
	 * Gets a map of all the threatening classes' threatening methods.
	 * 
	 * @return A map of all the threatening classes' threatening methods.
	 */
	private Map<ThreatClass, List<ThreatMethod>> getThreatMap() {
		Map<ThreatClass, List<ThreatMethod>> threatMap = 
				new HashMap<ThreatClass, List<ThreatMethod>>();
		for (Class<? extends ThreatClass> threatClass : threatClasses)
			try {
				ThreatClass threatClassInstance = threatClass.newInstance();
				threatMap.put(threatClassInstance, threatClassInstance
						.getThreatMethodInstances());
			} catch (InstantiationException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			}
		return threatMap;
	}

}
