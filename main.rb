#!/usr/bin/env ruby

#Author: C Juarez
#Description: Command line application that encrypts and decrypts strings with a key. It is based on two methods described
# in the book: Cryptography and Network Security Principles and Practices, 4th Ed by William Stallings.

require File.dirname(__FILE__) + "/Cypher.rb"

#Menu inicia
begin
  puts "Seleccione la opcion que desea realizar:\n[e]ncriptar\t[d]esencriptar:"
  funct = gets.chomp
  funct = funct[0,1].downcase
end while funct !='e' and funct != 'd'

puts "Inrese la cadena a encriptar/desencriptar:"
text = gets.chomp

puts "Ingrese la clave de encriptacion:"
clave = gets.chomp
#Termina menu
#
cy = Cypher.new

if funct == "e"
  encripted = cy.EncryptText(text,clave)
  puts "El texto encriptado es: #{encripted}"
elsif funct == "d"
  decripted = cy.DecryptText(text, clave)
  puts "El texto original era: #{decripted}"
else
  puts "Especifique la funcion: Encriptar o Desencriptar."
end
