package com.pers.smartproxy.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;  
public class ForEachExample {  
    public static void main(String[] args) {  
    
        final List<String> gamesList = new ArrayList<String>() {{
       add("Football");  
        add("Cricket");  
        add("Chess");  
        add("Hocky");  }};
        System.out.println("------------Iterating by passing lambda expression--------------");  
        gamesList.forEach(games -> {
        	if (games.equalsIgnoreCase("football")) {
        	gamesList.add("football1");
        	}
        });
          
    }  
}  
