package com.pers.smartproxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.db.Person;
import com.pers.smartproxy.db.PersonDAO;
import com.pers.smartproxy.health.DirectorySvcsHealthCheck;
import com.pers.smartproxy.health.ExtConnectorsHealthCheck;
import com.pers.smartproxy.representations.Tenancy;
import com.pers.smartproxy.services.DSEngine;

import io.dropwizard.Application;
import io.dropwizard.db.DataSourceFactory;
import io.dropwizard.hibernate.HibernateBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

/**
 * @author sathyh2
 * 
 *         Main class does three things a. registers webservice resources(using
 *         Jersey) b. spins up Jetty HTTP server c. embeds ApacheDS services
 *         within the instance
 *
 */

public class BootupApp extends Application<AppConfig> {

	final Logger logger = LoggerFactory.getLogger(BootupApp.class);

	/**
	 * Starts Jetty and embeds ApacheDS
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		new BootupApp().run(args);
	}
	
//	private final HibernateBundle<AppConfig> hibernate = new HibernateBundle<AppConfig>(Person.class) {
//        @Override
//        public DataSourceFactory getDataSourceFactory(AppConfig configuration) {
//            return configuration.getDatabaseAppDataSourceFactory();
//        }
//    };

    @Override
    public String getName() {
        return "dropwizard-hibernate";
    }

   
	/*
	 * (non-Javadoc)
	 * 
	 * @see io.dropwizard.Application#initialize(io.dropwizard.setup.Bootstrap)
	 */
	@Override
	public void initialize(Bootstrap<AppConfig> bootstrap) {
		// TODO commands
	//	   bootstrap.addBundle(hibernate);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.dropwizard.Application#run(io.dropwizard.Configuration,
	 * io.dropwizard.setup.Environment)
	 */
	@Override
	public void run(AppConfig configuration, Environment environment) throws Exception {
		final DSEngine dsEngine = new DSEngine(configuration);
//		final CrudResource crudResource = new CrudResource(dsEngine, configuration);
//		final AuthenticationResource endpointResource = new AuthenticationResource(dsEngine);
//
//		final TenantResource tenantResource = new TenantResource(dsEngine, configuration);
//		final UserTenantAuthResource userTenantAuth = new UserTenantAuthResource(dsEngine, configuration);
//		final UserTenantResource userTenantResource = new UserTenantResource(dsEngine, configuration);
//		dsEngine.getTenancyInterceptor().setEngine(dsEngine);
//		// register svcs
//		environment.jersey().register(crudResource);
//		environment.jersey().register(endpointResource);
//
//		environment.jersey().register(tenantResource);
//		environment.jersey().register(userTenantAuth);
//		environment.jersey().register(userTenantResource);
	//	 final PersonDAO personDAO = new PersonDAO(hibernate.getSessionFactory());

	//        final PersonResource personResource = new PersonResource(personDAO);

	  //      environment.jersey().register(personResource);
		// health checks
		environment.jersey().register(new HealthCheckResource(environment.healthChecks()));
		environment.healthChecks().register("dirsvcs", new DirectorySvcsHealthCheck(dsEngine));
		environment.healthChecks().register("extsvcs", new ExtConnectorsHealthCheck(dsEngine));
		logger.info("hostname: " + configuration.getHostName());
		logger.info("PORT Id: " + configuration.getPort());
		logger.info("started ApacheDS on port: " + configuration.getPort());
		// bootstrap sample tenants
//		if (configuration.getSampleTenant() != null && configuration.getSampleTenant().length > 1) {
//			bootstrapSampleTenants(configuration, tenantResource);
//		}
		// Set completion of bootup
		dsEngine.setIsFullyStarted(true);
		logger.info("system fully started now....");
	}

	/**
	 * @param configuration
	 * @param tenantResource
	 */
	protected void bootstrapSampleTenants(AppConfig configuration, final TenantResource tenantResource) {
		String[] tenants = configuration.getSampleTenant();
		for (String tenant : tenants) {
			String[] tenantAttrs = tenant.split(":");
			Tenancy newTenant = new Tenancy();
			newTenant.setTenantName(tenantAttrs[0]);
			newTenant.setSourceTenantDn(tenantAttrs[1]);
			newTenant.setSourceUsersDn(tenantAttrs[2]);
			if (tenantAttrs[3].equals("null")) {
				newTenant.setAttrsMap(" ");
			} else
				newTenant.setAttrsMap(tenantAttrs[3]);
			newTenant.setReadOnly(true);
			newTenant.setLdapType("apacheDs");
			newTenant.setResourceSetID("fdsfsdf");
			newTenant.setConnectionString(configuration.getSampeConnection());
			// add the sample tenant
			try {
				tenantResource.addNewTenant(newTenant);
			} catch (Exception e) {
				logger.warn("Exception " + e);
			}
		}
	}
}
