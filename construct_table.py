def d_term(x, s):
    numer = (2 ** 225)
    denom = 1
    result = numer // denom
    pi70 = 31415926535897932384626433832795028841971693993751058209749445923078164
    for i in range(500):
        numer = numer * pi70
        numer = numer * (x * x)

        denom = denom * (i + 1)
        denom = denom * (s * s)
        denom = denom * (10 ** 70)
        taylor = numer // denom

        if i % 2 == 0:
            taylor = -taylor
        result = result + taylor
    return result // s


if __name__ == "__main__":
    f = open('result.txt', 'w')

    s = (2 ** 25) + (2 ** 5)
    iteration = 216680088

    table = []
    for i in range(iteration):
        if i == 0:
            table.append(0)
        else:
            table.append(table[-1] + d_term(i, s))
        print("present compute : " + str(i))
    for i in range(iteration):
        table[i] = table[i] + ((2 ** 224) // s)

    for value in table:
        f.write(hex(value >> 32))
        f.write('\n')