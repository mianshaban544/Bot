# bot_admin.py
import os
import time
import json
import datetime
import requests
import discord
from discord.ext import commands

# ====== CONFIG ======
BOT_TOKEN = os.getenv("BOT_TOKEN", "MTQyOTU1NzMxMTYzNDE0OTU0Nw.GNwpaH.jgcPvam1t8R-xJDzJWC_brpCIG08Xisby9aJY8")
SERVER = os.getenv("SERVER_URL", "http://localhost:5000")
ADMIN_KEY = os.getenv("ADMIN_KEY", "adminkey")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

def _post(path, data):
    try:
        return requests.post(f"{SERVER}{path}", json=data,
                             headers={"X-ADMIN-KEY": ADMIN_KEY}, timeout=10)
    except Exception as e:
        class R: status_code=599; text=str(e)
        return R()

def _get(path, params=None):
    try:
        return requests.get(f"{SERVER}{path}", params=params,
                            headers={"X-ADMIN-KEY": ADMIN_KEY}, timeout=10)
    except Exception as e:
        class R: status_code=599; text=str(e)
        return R()

@bot.event
async def on_ready():
    print(f"✅ Bot logged in as {bot.user}")

# -------- Commands --------

@bot.command(help="Create user: !createuser <username> <password> <minutes(optional)>")
@commands.has_permissions(administrator=True)
async def createuser(ctx, username: str, password: str, minutes: int = 0):
    body = {
        "username": username.strip(),
        "password": password,
        "duration_minutes": minutes,
        "permissions": {"can_run_mine": True, "can_run_demorgan": True},
    }
    r = _post("/admin/create-user", body)
    await ctx.send(f"CreateUser → {r.status_code}\n{r.text[:1500]}")

@bot.command(help="Set perm: !setperm <username> <perm> <true/false> <minutes(optional)>")
@commands.has_permissions(administrator=True)
async def setperm(ctx, username: str, perm: str, value: str, minutes: int = 0):
    username = username.strip()
    r = _get("/admin/get-user", {"username": username})
    if r.status_code != 200:
        await ctx.send(f"❌ setperm failed. get-user → {r.status_code}\n{r.text[:300]}")
        return
    u = r.json()
    perms = u.get("permissions", {})
    perms[perm] = value.lower() in ("true","1","yes","on")
    if minutes > 0:
        expiry = int(time.time()) + minutes*60
        perms.setdefault("_expiry", {})[perm] = expiry
    r2 = _post("/admin/set-permissions", {"username": username, "permissions": perms})
    await ctx.send(f"SetPerm → {r2.status_code}\n{r2.text[:300]}")

@bot.command(help="User info: !userinfo <username>")
@commands.has_permissions(administrator=True)
async def userinfo(ctx, username: str):
    r = _get("/admin/get-user", {"username": username.strip()})
    if r.status_code != 200:
        await ctx.send(f"❌ userinfo failed → {r.status_code}\n{r.text[:300]}")
        return

    u = r.json()
    valid_until = u.get("valid_until")
    readable = "∞ (no expiry)"
    if valid_until:
        exp_time = datetime.datetime.fromtimestamp(valid_until)
        left_min = int((valid_until - time.time()) / 60)
        if left_min < 60:
            readable = f"{left_min} min left ({exp_time.strftime('%Y-%m-%d %H:%M:%S')})"
        else:
            readable = f"{round(left_min/60,1)} hr left ({exp_time.strftime('%Y-%m-%d %H:%M:%S')})"

    perms_text = json.dumps(u.get("permissions", {}), indent=2)
    await ctx.send(
        f"👤 **{u.get('username')}**\n"
        f"🆔 discord_id: `{u.get('discord_id')}`\n"
        f"⏰ valid_until: {readable}\n"
        f"🪪 permissions: ```json\n{perms_text}\n```"
    )

@bot.command(name="nhelp", help="Show all admin commands")
async def custom_help(ctx):
    embed = discord.Embed(
        title="🛠️ Ninja Admin Bot — Command List",
        description="Yahan sari available commands aur unka use likha hai 💡",
        color=discord.Color.blurple()
    )

    embed.add_field(
        name="🧱 !createuser <username> <password> [minutes]",
        value="Naya user banata hai.\n**Example:** `!createuser ninja123 pass321 120` (valid 2 hours)",
        inline=False
    )

    embed.add_field(
        name="⚙️ !setperm <username> <permission> <true/false> [minutes]",
        value="User ke permissions set karta hai.\n**Example:** `!setperm ninja123 can_run_fuelm true 30` (30 min ke liye)",
        inline=False
    )

    embed.add_field(
        name="📜 !userinfo <username>",
        value="User ke permissions aur expiry time dikhata hai.\n**Example:** `!userinfo ninja123`",
        inline=False
    )

    embed.add_field(
        name="❌ !deleteuser <username>",
        value="User ko database se hata deta hai.\n**Example:** `!deleteuser ninja123`",
        inline=False
    )

    embed.add_field(
        name="🆘 !help",
        value="Ye hi command jo sab explain karti hai 😄",
        inline=False
    )

    embed.set_footer(text="Made with ❤️ by Ustad Ninja")
    await ctx.send(embed=embed)


@bot.command(help="Delete user: !deleteuser <username>")
@commands.has_permissions(administrator=True)
async def deleteuser(ctx, username: str):
    r = _post("/admin/delete-user", {"username": username.strip()})
    await ctx.send(f"DeleteUser → {r.status_code}\n{r.text[:300]}")

bot.run(BOT_TOKEN)