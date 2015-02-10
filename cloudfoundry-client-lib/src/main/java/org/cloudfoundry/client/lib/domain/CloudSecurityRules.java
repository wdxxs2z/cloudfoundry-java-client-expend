package org.cloudfoundry.client.lib.domain;

public class CloudSecurityRules {

	private String protocol;
	
	private String destination;
	
	private String ports;
	
	private Integer type;
	
	private Integer code;
	
	private Boolean log;

	public CloudSecurityRules() {
	}

	public CloudSecurityRules(String protocol, String destination) {
		this.protocol = protocol;
		this.destination = destination;
	}

	public CloudSecurityRules(String protocol, String destination, String ports) {
		this.protocol = protocol;
		this.destination = destination;
		this.ports = ports;
	}

	public CloudSecurityRules(String protocol, String destination,
			String ports, Boolean log) {
		this.protocol = protocol;
		this.destination = destination;
		this.ports = ports;
		this.log = log;
	}
	
	public CloudSecurityRules(String protocol, String destination,
			Integer type, Integer code) {
		this.protocol = protocol;
		this.destination = destination;
		this.type = type;
		this.code = code;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getDestination() {
		return destination;
	}

	public void setDestination(String destination) {
		this.destination = destination;
	}

	public String getPorts() {
		return ports;
	}

	public void setPorts(String ports) {
		this.ports = ports;
	}

	public Integer getType() {
		return type;
	}

	public void setType(Integer type) {
		this.type = type;
	}

	public Integer getCode() {
		return code;
	}

	public void setCode(Integer code) {
		this.code = code;
	}

	public Boolean getLog() {
		return log;
	}

	public void setLog(Boolean log) {
		this.log = log;
	}
}
