+++
title = "DDC Qualifiers 2025"
date = "2022-03-16"
weight = 0

[taxonomies]
tags=[
    "web", "cookie", "auth",
    "crypto", "misc",
    "boot2root", "privesc", "sqli", 
    "ctf"
]
ctf=["DDC"]
+++


# Crypto


# Boot2Root


# Misc 

## DDC admin bot

**TLDR**
1. User **kaj** sends `!verifyme` 
2. Bot sends message in `verification_channel`: `f"{user.mention} has requested verification. Moderators with {mod_role.mention}, please verify."`
3. `msg = f"{user.mention} has requested verification. Moderators with {mod_role.mention}, please verify."`
4. User with moderator role reacts with ✅ on message
5. Do Exploit
    - send spoof message in own discord server 
    - react to it while having the the role `moderator`
6. User **kaj** is assigned role `member`
7. Read flag in new channel

**Writeup**

In this challenge we have to exploit a Discord bot. There is an instance of the bot running on the challenge Discord server. 

When a user types `!verifyme` then the bot sends the message: 
```py
msg = f"{user.mention} has requested verification. Moderators with {mod_role.mention}, please verify."
``` 
to the "verification channel".

Our goal is to have a user, with the `mod_role`, react with to the message sent by the bot.

However we do not have access to this channel nor do we have the `mod_role`

However, the bot has a vulnerability!

The important part is the `check` function in:

```python
    try:
        # Wait for a moderator to react with the correct emoji
        reaction, moderator = await bot.wait_for('reaction_add', check=check)
        # Assign the "member" role to the user after verification
        member_role = discord.utils.get(guild.roles, name=MEMBER_ROLE_NAME)
        if member_role is None:
            await ctx.send("Member role not found in the server.")
        else:
            await user.add_roles(member_role)
            await verification_channel.send(
                f"{user.mention} has been verified by {moderator.mention} and given the {member_role.name} role."
            )
    <...>
``` 
Notice the conditions:
```python
    def check(reaction, reactor):
        return (
            str(reaction.emoji) == "✅"
            and reaction.message.content == msg
            and reaction.message.channel.name == VERIFICATION_CHANNEL_NAME
            and any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])
        )
 ``` 

Since the constants just are strings:

```python
MODERATOR_ROLE_NAME = "moderator"
MEMBER_ROLE_NAME = "member"
VERIFICATION_CHANNEL_NAME = "verification" 
```


My setup:

- Create a second Discord server (let me denote with `fake server`)
- Invite the same "instance" of the Discord bot to the `fake server` using this method: https://ctftime.org/writeup/33674

<!--Additionally I spun up the docker image, with following modifications (messy):-->
<!---->
<!--```python-->
<!--    def check(reaction, reactor):-->
<!--        print("ENTERING check")-->
<!--        print(f"reaction emoji:{str(reaction.emoji)}, {reaction.message.content == msg}, {reaction.message.channel.name == VERIFICATION_CHANNEL_NAME}, {any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])}")-->
<!--        if str(reaction.emoji) != "✅":-->
<!--            print("Wrong:")-->
<!--            print(str(reaction.emoji))-->
<!--        if reaction.message.content != msg:-->
<!--            print("Wrong:")-->
<!--            print(f"rmsg:{reaction.message.content}")-->
<!--            print(f"msg: {msg}")-->
<!--        if (any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])):-->
<!--            print("Wrong:")-->
<!--            print("reactor.roles", reactor.roles)-->
<!--        return (-->
<!--            str(reaction.emoji) == "✅"-->
<!--            and reaction.message.content == msg-->
<!--            and reaction.message.channel.name == VERIFICATION_CHANNEL_NAME-->
<!--            and any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])-->
<!--        )-->
<!---->
<!--```-->

We want to spoof a message and react to it in our own server.

But first you need some IDs (enable developer mode in Discord)

- Your User ID. (right-click yourself or something)
- Find user with the `moderator` role and get the Role ID (right-click)
    - `1293636473291014184`

To construct the message:

Send `!verifyme` in the fake server to get:
```
<@USER_ID> has requested verification. Moderators with <@&FAKE_MODERATOR_ROLE_ID>, please verify.
```
Then replace role id and send in fake server:

```
<@SMAVL_ID> has requested verification. Moderators with <@&1293636473291014184>, please verify.
```
then react to the message with ✅, and you should get the `member` role in the challenge server



Source code:

```python
#!/bin/python3
import discord
from discord.ext import commands
import os

# Intents setup
intents = discord.Intents.default()
intents.message_content = True
intents.members = True  # Required to access member updates and role management

# Bot prefix and intents
bot = commands.Bot(command_prefix="!", intents=intents)

# IDs for roles and channel names
TOKEN = os.getenv('DISCORD_TOKEN')
MODERATOR_ROLE_NAME = "moderator"
MEMBER_ROLE_NAME = "member"
VERIFICATION_CHANNEL_NAME = "verification" 


@bot.event
async def on_ready():
    print(f'Bot {bot.user.name} has connected to Discord!')

async def get_or_create_verification_channel(guild):
    # Look for the verification channel by name
    verification_channel = discord.utils.get(guild.text_channels, name=VERIFICATION_CHANNEL_NAME)

    # If the channel doesn't exist, create it
    if verification_channel is None:
        print(f"Verification channel not found. Creating a new one...")
        verification_channel = await guild.create_text_channel(
            VERIFICATION_CHANNEL_NAME,
            topic="Channel for moderator to verify users",
            reason="Create verification channel for user verification",
        )
        print(f"Created verification channel: {verification_channel.name}")

    return verification_channel

# Command to request verification
@bot.command(name='verifyme')
async def request_verification(ctx):
    user = ctx.author
    guild = ctx.guild

    # Get the moderator and member roles
    mod_role = discord.utils.get(guild.roles, name=MODERATOR_ROLE_NAME)
    if mod_role is None:
        await ctx.send("Moderator role not found in the server.")
        return

    # Get or create the verification channel
    verification_channel = await get_or_create_verification_channel(guild)

    # Notify the user their request has been sent
    await ctx.send(f"{user.mention}, your verification request has been sent to the moderators.")

    # Send the verification request to the verification channel
    msg = f"{user.mention} has requested verification. Moderators with {mod_role.mention}, please verify."
    verification_msg = await verification_channel.send(msg)
    
    # Ask moderators to react to verify the user
    await verification_msg.add_reaction("✅")

    # Create a check function to confirm it's the correct reaction from a moderator
    def check(reaction, reactor):
        return (
            str(reaction.emoji) == "✅"
            and reaction.message.content == msg
            and reaction.message.channel.name == VERIFICATION_CHANNEL_NAME
            and any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])
        )

    try:
        # Wait for a moderator to react with the correct emoji
        reaction, moderator = await bot.wait_for('reaction_add', check=check)
        # Assign the "member" role to the user after verification
        member_role = discord.utils.get(guild.roles, name=MEMBER_ROLE_NAME)
        if member_role is None:
            await ctx.send("Member role not found in the server.")
        else:
            await user.add_roles(member_role)
            await verification_channel.send(
                f"{user.mention} has been verified by {moderator.mention} and given the {member_role.name} role."
            )

    except Exception as e:
        await verification_channel.send(f"An error occurred during the verification process: {str(e)}")

# Run the bot
bot.run(TOKEN)

```

```python
 ``` 

To exploit the 


smavl id:
103595801464295424
veri msg:
<@103595801464295424> has requested verification. Moderators with <@&>, please verify.

true ddc:
mod:
1293636473291014184


first !verifyme in ddc_server

then copy the mod id:

1293636473291014184

then add bot to own server and send msg:

<@103595801464295424> has requested verification. Moderators with <@&1293636473291014184>, please verify.
then react to it



