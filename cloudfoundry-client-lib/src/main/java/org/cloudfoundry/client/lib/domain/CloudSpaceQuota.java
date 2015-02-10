package org.cloudfoundry.client.lib.domain;


public class CloudSpaceQuota extends CloudEntity {

	private boolean nonBasicServicesAllowed = false;
    private int totalServices;
    private int totalRoutes;
    private long memoryLimit;
    private String organization_guid;
    private CloudOrganization organization;
    
    public CloudSpaceQuota(Meta meta, String name, boolean nonBasicServicesAllowed,
            int totalServices, int totalRoutes, long memoryLimit , String organization_guid) {
        super(meta, name);
        this.totalServices=totalServices;
        this.totalRoutes=totalRoutes;
        this.memoryLimit=memoryLimit;
        this.nonBasicServicesAllowed = nonBasicServicesAllowed;
        this.organization_guid = organization_guid;

    }
    
    public String getOrganization_guid() {
		return organization_guid;
	}

	public void setOrganization_guid(String organization_guid) {
		this.organization_guid = organization_guid;
	}

	public CloudSpaceQuota(Meta meta, String name){
    	super(meta, name);
    }

	public boolean isNonBasicServicesAllowed() {
		return nonBasicServicesAllowed;
	}

	public void setNonBasicServicesAllowed(boolean nonBasicServicesAllowed) {
		this.nonBasicServicesAllowed = nonBasicServicesAllowed;
	}

	public int getTotalServices() {
		return totalServices;
	}

	public void setTotalServices(int totalServices) {
		this.totalServices = totalServices;
	}

	public int getTotalRoutes() {
		return totalRoutes;
	}

	public void setTotalRoutes(int totalRoutes) {
		this.totalRoutes = totalRoutes;
	}

	public long getMemoryLimit() {
		return memoryLimit;
	}

	public void setMemoryLimit(long memoryLimit) {
		this.memoryLimit = memoryLimit;
	}

	public CloudOrganization getOrganization() {
		return organization;
	}

	public void setOrganization(CloudOrganization organization) {
		this.organization = organization;
	}	
}
