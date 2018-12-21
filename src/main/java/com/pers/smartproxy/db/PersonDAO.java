package com.pers.smartproxy.db;


import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.List;

public class PersonDAO extends AbstractDAO<Person> {
	public PersonDAO(SessionFactory factory) {
        super(factory);
    }

	 public List<Person> findAll() {
	        return list(namedQuery("com.virtustream.coreservices.rolodex.db.Person.findAll"));
	    }

    public Person findById(int id) {
        return (Person) currentSession().get(Person.class, id);
    }

    public void delete(Person person) {
        currentSession().delete(person);
    }

    public void update(Person person) {
        currentSession().saveOrUpdate(person);
    }

    public Person insert(Person person) {
        return persist(person);
    }
}