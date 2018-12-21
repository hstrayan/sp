package com.pers.smartproxy.utils;

import java.util.ArrayList;
import java.util.List;

interface Sayable{  
    void say();  
}  

interface HelloWorld{
	public String hello();
}

public class MethodReference {  
    public static void saySomething(){  
        System.out.println("Hello, this is static method.");  
    }  
    
    public static String sayHello() {
		return "Hello World";
    	
    }
    public static void main(String[] args) {  
        // Referring static method  
        Sayable sayable = MethodReference::saySomething;  
        // Calling interface method  
        sayable.say(); 
        
        HelloWorld hello = MethodReference::sayHello;
        
        System.out.println(hello.hello());
        
        List<String> items = new ArrayList<>();
    	items.add("A");
    	items.add("B");
    	items.add("C");
    	items.add("D");
    	items.add("E");

    	//lambda
    	//Output : A,B,C,D,E
    	items.forEach(item->System.out.println(item));
    		
    	//Output : C
    	items.forEach(item->{
    		if("C".equals(item)){
    			items.remove(item);}
    			System.out.println(item);
    	//	}
    	});
    }  
    
}  