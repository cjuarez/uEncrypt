#Author: C Juarez
#Description: Command line application that encrypts and decrypts strings with a key. It is based on two methods described
# in the book: Cryptography and Network Security Principles and Practices, 4th Ed by William Stallings.

class Cypher
  #constructor
  def initialize()
    #Crea un array con los caracteres ascii desde el espacio (' ') hasta
    #la llave cerrada '}'. Este array puede aumentar o disminuir tanto como se
    #necesite. De esto depende que caracteres será posible encriptar
    @alphabet = ('a'..'z').to_a + ('0'..'9').to_a + (' '..'/').to_a
    @top = @alphabet.size
  end
  #metodos publicos.
  #Encripta el texto plano con la llave indicada
  def EncryptText(plaintext,key)
    encripted = EncrpytWithSubstitution(plaintext,key)
    encripted = EncryptWithPermutation(encripted,key)
  end

  #Desencripta el texto cifrado con la llave indicada
  def DecryptText(cypher,key)
    decripted = DecryptWithPermutation(cypher,key)
    decripted = DecryptWithSubstitution(decripted,key)
  end

  #Todos los metodos siguientes son privados
  private
  #Encripta el texto plano por substitucion
  def EncrpytWithSubstitution(plaintext,key)
    encryptedText = ""
    key = IncreaseKey(key,plaintext)
    i = 0
    while i<plaintext.size
      #Con cada uno de los caracteres de plaintext y su caracter de
      #key correspondiente, se obtiene el caracter encriptado y se
      #concatena en encryptedText
      encryptedText+=GetCharEncrypted(plaintext[i,1],key[i,1]).to_s
      i+=1
    end
    return encryptedText
  end

  #Descifra la cadena por substitucion
  def DecryptWithSubstitution(cypher,key)
    decrpytedText = ""
    key = IncreaseKey(key,cypher)
    i = 0
    while i<cypher.size
      #Con cada uno de los caracteres de cypher y su caracter de
      #key correspondiente, se obtiene el caracter desencriptado y
      #se concatena en decryptedText
      decrpytedText+=GetCharDecrypted(cypher[i,1],key[i,1]).to_s
      i+=1
    end
    return decrpytedText
  end
  
  #Aumenta la llave para que coincida en tamaño con el texto
  def IncreaseKey(key,text)
    i=0
    while key.size<text.size
      key+=key[i,1].to_s
      i+=1
    end
    return key
  end
  
  #Encripta un caracter con el caracter correspondiente de la clave
  def GetCharEncrypted(pt,k)
    #Posicion actual de pt en el alfabeto
    position = @alphabet.index pt
    
    #Valor que k hara que pt se mueva
    #Se utiliza el mismo alfabeto pero al reves
    #de esta forma 'a' como texto tiene posicion 0
    #pero como clave recorre n-0 espacios (donde n es
    #la cantidad máxima de caracteres en @alphabet
    change = @alphabet.reverse.index k
    
    #Atrapa un error. Sucede si pt o k no existen en @alphabet
    if position == nil or change==nil
      puts "Position #{position}"
      puts "#{k} Change #{change}"
    end

    #La nueva posicion (caracter encriptado)
    newPosition = position+change
    
    #Si se pasa del máximo de caracteres en @alphabet
    #continua desde el inicio
    if (newPosition>@top-1)
      newPosition = newPosition-@top
    end
    return @alphabet[newPosition]
  end
  
  #Desencripta un caracter con el caracter correspondiente de la clave
  #Mismo proceso que en GetCharEncrypted(pt,k) pero inverso.
  def GetCharDecrypted(cy,k)
    #Posicion actual y cambio que aplica k
    position = @alphabet.index cy
    change = @alphabet.reverse.index k
    
    #Atrapa error
    if position == nil or change==nil
      puts "Position #{position}"
      puts "#{k} Change #{change}"
    end
    newPosition = position-change
    #Si llegamos al inicio de @alphabet, continua desde el final
    if (newPosition<0)
      newPosition = @top+newPosition
    end
    return @alphabet[newPosition]
  end
  
  #Encripta la cadena por permutación
  def EncryptWithPermutation(plaintext,key)
    size = plaintext.size
    if size==1
      return plaintext
    end
    matriz = []
    fila = []
    #Obtenemos la cantidad de columnas
    #desde 5 hasta 2 evaluamos si alguno es divisor
    #entero de size. Si sí, esa es la cantidad de columnas
    #Si no, el size es la cantidad de columnas
    if size%5 == 0
      columnas=5
    elsif size%4 == 0
      columnas=4
    elsif size%3 == 0
      columnas=3
    elsif size%2 == 0
      columnas=2
    else
      columnas=size
    end
    i = 0
    while i<size
      fila = []
      #Creamos una fila con caracteres desde i hasta i+columnas
      for j in 0..columnas-1
        char = plaintext[i+j,1]
        fila.push(char.to_s)
      end
      #Colocamos esa fila en la matriz
      matriz.push(fila)
      i+=columnas
    end
    #Obtenemos la llave para permutación utilizando la misma cadena
    #que para substitucion
    key = getKeyForPermutation(key,columnas)
    salida = ""
    fils = size/columnas
    #Ordena las columnas de acuerdo a keyForPermutation.
    #Esto es, si la llave es 4213, obtiene la columna 4
    #y la coloca al principio, luego la 2 y la adjunta, etc.
    for col in key
      for fil in 0..fils-1
        salida += matriz[fil][col.to_i]
      end
    end
    return salida
  end
  
  
  #Desencripta la cadena por permutación
  #
  def DecryptWithPermutation(cypher,key)
    size = cypher.size
    if size==1
      return cypher
    end
    if size%5 == 0
      columnas=5
    elsif size%4 == 0
      columnas=4
    elsif size%3 == 0
      columnas=3
    elsif size%2 == 0
      columnas=2
    else
      columnas=size
    end
    key = getKeyForPermutation(key,columnas)
    fils = size/columnas
    
    #Divide cypher en un array con las filas
    salida = cypher.scan(/.{#{fils}}/)
    output = ""
    
    #Obtiene una cadena con las filas en orden
    for col in 0..salida.size-1
      colOrder = key.index col.to_s
      output += salida[colOrder]
    end
  
    final = ""
    i = 0
    #Obtiene la cadena original con la que fue formada
    #la matriz de permutacion
    while i<fils
      for j in 0..columnas-1
        final += output[i+j*fils,1]
      end
      i+=1
    end
    return final
  end
  
  
  #OBtiene la llave de permutacion (orden de columnas) a partir
  #de una llave de texto, utilizando el valor de cada caracter
  #en el alfabeto y concatenandolos todos.
  def getKeyForPermutation(key,columnas)
    i=0
    salida = ""
    while i<key.size
      index = @alphabet.index key[i,1] #obtiene su posicion en el alfabeto
      salida+=index.to_s #concatena todos los numeros
      i+=1
    end
    output = salida.split(//) #dividelos en un array
    #elimina los mayores a la cantidad de columnas - 1
    output.delete_if {|x| x > (columnas-1).to_s }
    #eliminamos los repetidos
    output.uniq!
    #agregamos los que falten para tener todas las columnas
    for i in 0..columnas-1
      if !output.include?(i.to_s)
        output<<i.to_s
      end
    end
    return output
  end
end

