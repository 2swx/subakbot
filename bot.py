
import discord, base64, hashlib, os
client = discord.Client()

@client.event
async def on_ready():
    print('We have logged in as {0.user}'.format(client))
    activity = discord.Game(name="나는 시원한 수박봇이얌")
    await client.change_presence(activity=activity)
@client.event
async def on_message(message):
  if message.content == '!도움말':
    des = '수박봇은 암호를 해독하거나 여러가지 형태로 문자를 변환하는 봇입니다.\n!바이너리 <문자> : 문자를 바이너리로 변경합니다.\n?바이너리 <숫자>: 바이너리를 문자로 변환합니다.\n!base(16, 32, 64, 85) <문자> : base(16, 32, 64, 85)으로 인코딩합니다.\n?base(16, 32, 64, 85) <문자> : base(16, 32, 64, 85)으로 디코딩합니다.\n!sha(1, 2, 256, 512) : sha(1, 224, 256, 512)로 인코딩합니다.\n!md5 <문자> : md5로 인코딩합니다.\n!subak0 : 수박봇 알고리즘으로 문자를 암호화합니다.'
    embed = discord.Embed(title = '수박봇 도움말', description=des)
    await message.channel.send(embed = embed)
  if message.content.startswith('!바이너리 '):
    try:
      text = message.content[6:]
      after = '0' + ' 0'.join(format(ord(x), 'b') for x in text)
      embed = discord.Embed(title = '문자열 to 바이너리', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '문제가 발생했습니다.')
      await message.channel.send(embed = embed)
  
  if message.content.startswith('?바이너리 '):
    try:
      text = message.content[6:]
      binary_values = text.split(" ")
      ascii_string = ""
      for binary_value in binary_values:
          an_integer = int(binary_value, 2)
          ascii_character = chr(an_integer)
          ascii_string += ascii_character
      
      after = ascii_string
      embed = discord.Embed(title = '바이너리 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 숫자를 띄어쓰기로 분리하여 적어주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('!base64 '):
    try:
      text = message.content[8:]
      after = base64.b64encode(text.encode('utf-8')).decode().replace("b'","").replace("'", "")
      embed = discord.Embed(title = '문자열 to base64', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('?base64 '):
    try:
      text = message.content[8:]
      after = base64.b64decode(text.encode('utf-8')).decode()
      embed = discord.Embed(title = 'base64 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('!base32 '):
    try:
      text = message.content[8:]
      after = base64.b32encode(text.encode('utf-8')).decode().replace("b'","").replace("'", "")
      embed = discord.Embed(title = '문자열 to base32', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('?base32 '):
    try:
      text = message.content[8:]
      after = base64.b32decode(text.encode('utf-8')).decode()
      embed = discord.Embed(title = 'base32 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)
  
  if message.content.startswith('!base16 '):
    try:
      text = message.content[8:]
      after = base64.b16encode(text.encode('utf-8')).decode().replace("b'","").replace("'", "")
      embed = discord.Embed(title = '문자열 to base16', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('?base16 '):
    try:
      text = message.content[8:]
      after = base64.b16decode(text.encode('utf-8')).decode()
      embed = discord.Embed(title = 'base16 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('!base85 '):
    try:
      text = message.content[8:]
      after = base64.b85encode(text.encode('utf-8')).decode()
      embed = discord.Embed(title = '문자열 to base85', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('?base85 '):
    try:
      text = message.content[8:]
      after = base64.b85decode(text.encode('utf-8')).decode()
      embed = discord.Embed(title = 'base85 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)
  
  if message.content.startswith('!sha256 '):
    try:
      text = message.content[8:]
      after = hashlib.sha256(text.encode()).hexdigest()
      embed = discord.Embed(title = 'sha256 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)
  
  if message.content.startswith('!sha1 '):
    try:
      text = message.content[6:]
      after = hashlib.sha1(text.encode()).hexdigest()
      embed = discord.Embed(title = 'sha1 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)
  if message.content.startswith('!sha224 '):
    try:
      text = message.content[8:]
      after = hashlib.sha224(text.encode()).hexdigest()
      embed = discord.Embed(title = 'sha224 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('!sha512 '):
    try:
      text = message.content[8:]
      after = hashlib.sha512(text.encode()).hexdigest()
      embed = discord.Embed(title = 'sha512 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)

  if message.content.startswith('!md5 '):
    try:
      text = message.content[5:]
      after = hashlib.md5(text.encode()).hexdigest()
      embed = discord.Embed(title = 'md5 to 문자열', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      await message.channel.send(embed = embed)
  
  if message.content.startswith('!subak0 '):
    try:
      text = message.content[8:]
      after = '0' + ' 0'.join(format(ord(x), 'b') for x in text).replace(' ', 'p')
      i = 0
      after = hashlib.sha256(after.encode()).hexdigest()
      after = hashlib.sha512(after.encode()).hexdigest()
      after = hashlib.sha1(after.encode()).hexdigest()
      after = base64.b16encode(after.encode('utf-8')).decode().replace("b'","").replace("'", "")
      after = after.replace('0', '수').replace('1', '박').replace('2', '봇').replace('3', '후').replace('4', '스').replace('5', '따').replace('6', '꾸').replace('7', '미').replace('8', '뉴').replace('9', '민')
      embed = discord.Embed(title = '문자열 to 수박알고리즘 - 0', description = f'**변환전**\n{text}\n**변환후**\n``{after}``')
      await message.channel.send(embed=embed)
    except Exception as ex:
      embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
      print(ex)
      await message.channel.send(embed = embed)

    except Exception as ex:
        embed = discord.Embed(title = '안내', description = '제대로된 문자를 입력해주세요.')
        print(ex)
        await message.channel.send(embed = embed)
access_token = os.environ["BOT_TOKEN"] 
client.run(access_token)
