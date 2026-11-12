"""Visual atmosphere for the web app: smoke, rendered with plain CSS.

No JavaScript and no external assets. Both effects honour the operating
system's "reduce motion" setting, and drifting smoke never intercepts clicks
(``pointer-events: none``), so it can't get in the way of the evidence.
"""

from __future__ import annotations

# A few soft, blurred puffs that rise, swell and fade, staggered so the plume
# looks continuous. Shown beside the chat while Marlowe works.
SMOKE_LOADER = """
<style>
.mw-loader {display:flex; align-items:flex-end; gap:.9rem; padding:.4rem 0 .6rem;}
.mw-plume {position:relative; width:60px; height:80px;}
.mw-ember {position:absolute; bottom:0; left:22px; width:12px; height:4px;
  border-radius:2px; background:#d4a24c; box-shadow:0 0 8px 2px rgba(212,162,76,.55);
  animation:mw-glow 2.4s ease-in-out infinite;}
.mw-puff {position:absolute; bottom:4px; left:18px; width:24px; height:24px;
  border-radius:50%; background:radial-gradient(circle, rgba(232,225,211,.8) 0%,
  rgba(232,225,211,0) 70%); filter:blur(3px); opacity:0;
  animation:mw-rise 3s ease-out infinite;}
.mw-puff:nth-child(3) {animation-delay:.75s;}
.mw-puff:nth-child(4) {animation-delay:1.5s;}
.mw-puff:nth-child(5) {animation-delay:2.25s;}
.mw-loader-text {font-family:"Courier Prime","Courier New",Courier,monospace;
  opacity:.85; padding-bottom:.15rem;}
@keyframes mw-rise {
  0%   {transform:translate(0,0) scale(.5); opacity:0;}
  15%  {opacity:.9;}
  50%  {transform:translate(9px,-36px) scale(1.6);}
  100% {transform:translate(-7px,-70px) scale(2.8); opacity:0;}
}
@keyframes mw-glow {50% {box-shadow:0 0 12px 4px rgba(212,162,76,.8);}}
@media (prefers-reduced-motion: reduce) {
  .mw-puff {animation:none; opacity:.35;}
  .mw-ember {animation:none;}
}
</style>
<div class="mw-loader" role="status">
  <div class="mw-plume" aria-hidden="true">
    <div class="mw-ember"></div>
    <div class="mw-puff"></div><div class="mw-puff"></div>
    <div class="mw-puff"></div><div class="mw-puff"></div>
  </div>
  <span class="mw-loader-text">{message}</span>
</div>
"""

# A wide, faint bank of smoke that drifts across the top of the page about
# once a minute and is invisible the rest of the time.
DRIFTING_SMOKE = """
<style>
.mw-drift {position:fixed; top:4rem; left:0; width:55vw; height:220px;
  pointer-events:none; z-index:999990; opacity:0;
  background:
    radial-gradient(ellipse 30% 40% at 20% 55%, rgba(225,218,205,.10), transparent 70%),
    radial-gradient(ellipse 25% 35% at 45% 40%, rgba(225,218,205,.08), transparent 70%),
    radial-gradient(ellipse 35% 30% at 70% 60%, rgba(225,218,205,.07), transparent 70%);
  filter:blur(14px);
  animation:mw-drift 70s linear infinite; animation-delay:8s;}
@keyframes mw-drift {
  0%   {transform:translateX(-60vw) scaleY(.8); opacity:0;}
  3%   {opacity:1;}
  22%  {transform:translateX(110vw) scaleY(1.25); opacity:.9;}
  25%, 100% {transform:translateX(120vw); opacity:0;}
}
@media (prefers-reduced-motion: reduce) { .mw-drift {display:none;} }
</style>
<div class="mw-drift" aria-hidden="true"></div>
"""


def smoke_loader(message: str) -> str:
    """HTML for the smoke loading indicator, with ``message`` beside it."""
    from html import escape

    return SMOKE_LOADER.replace("{message}", escape(message))
