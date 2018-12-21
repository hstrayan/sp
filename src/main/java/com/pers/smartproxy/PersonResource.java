package com.pers.smartproxy;

import io.dropwizard.hibernate.UnitOfWork;

import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

import com.pers.smartproxy.db.Person;
import com.pers.smartproxy.db.PersonDAO;

import java.util.List;

@Path("/person")
@Consumes({MediaType.APPLICATION_JSON})
@Produces({MediaType.APPLICATION_JSON})
public class PersonResource {

    PersonDAO personDAO;

    public PersonResource(PersonDAO personDAO) {
        this.personDAO = personDAO;
    }

    @GET
    @UnitOfWork
    public List<Person> getAll(){
        return personDAO.findAll();
    }

    @GET
    @Path("/{id}")
    @UnitOfWork
    public Person get(@PathParam("id") Integer id){
        return personDAO.findById(id);
    }

    @POST
    @UnitOfWork
    public Person add(@Valid Person person) {
        Person newPerson = personDAO.insert(person);

        return newPerson;
    }

    @PUT
    @Path("/{id}")
    @UnitOfWork
    public Person update(@PathParam("id") Integer id, @Valid Person person) {
        person = person.setId(id);
        personDAO.update(person);

        return person;
    }

    @DELETE
    @Path("/{id}")
    @UnitOfWork
    public void delete(@PathParam("id") Integer id) {
        personDAO.delete(personDAO.findById(id));
    }
}
