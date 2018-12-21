package com.pers.smartproxy.utils;

interface speak {
	public String speakHindi(String hindi);
	
	
}

public class TestAnonymous {

	public static void main(String[] args) {
		//String hindi = "hindi";
		speak myspeak = new speak() {

			@Override
			public String speakHindi(String hindi) {
				System.out.println("i am speaking "+ hindi);
				return "ok spoke";
				
			}

//			@Override
//			public void speakTamil() {
//				System.out.println("i am speaking tamil");
//				
//			}
			
			
		};
		
		String hindi1 = myspeak.speakHindi("hindi");
		System.out.println(hindi1);
	//	myspeak.speakTamil();
		
		// using lambdas
		
		speak myspeak2 = (String hindi) -> {
			System.out.println("i am speaking "+ hindi);
			return "ok spoke";
			
		};
		String hindi2 = myspeak2.speakHindi("hindi");
		System.out.println(hindi2);
	}
}
