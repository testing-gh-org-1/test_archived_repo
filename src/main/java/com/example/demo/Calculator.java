package com.example.demo;

public class Calculator {
    
    public int add(int a, int b) {
        return a + b;
    }
    
    public int subtract(int a, int b) {
        return a - b;
    }
    
    public int multiply(int a, int b) {
        return a * b;
    }
    
    public double divide(int a, int b) {
        if (b == 0) {
            throw new ArithmeticException("Cannot divide by zero");
        }
        return (double) a / b;
    }
    
    public static void main(String[] args) {
        Calculator calc = new Calculator();
        
        System.out.println("Addition: 10 + 5 = " + calc.add(10, 5));
        System.out.println("Subtraction: 10 - 5 = " + calc.subtract(10, 5));
        System.out.println("Multiplication: 10 * 5 = " + calc.multiply(10, 5));
        System.out.println("Division: 10 / 5 = " + calc.divide(10, 5));
    }
}
