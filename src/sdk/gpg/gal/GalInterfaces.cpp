#include "Class.hpp"
#include "CursorContext.hpp"
#include "DrawIndexedContext.hpp"
#include "EffectMacro.hpp"
#include "Error.hpp"
#include "Head.hpp"
#include "Texture.hpp"
#include "VertexFormat.hpp"

#include <cstring>
#include <new>

namespace gpg::gal
{
  /**
   * Address: 0x009044C0 (FUN_009044C0, gpg::gal::VertexFormat::VertexFormat)
   *
   * What it does:
   * Restores base vertex-format vtable ownership and clears three runtime
   * state lanes used by derived backend wrappers.
   */
  VertexFormat::VertexFormat()
    : mReserved04{}
    , mState0C(0)
    , mState10(0)
    , mState14(0)
  {}

  /**
   * Address: 0x00903300 (FUN_00903300)
   *
   * What it does:
   * Initializes one abstract texture base lane by installing the class
   * vtable.
   */
  Texture::Texture() = default;
} // namespace gpg::gal

namespace gpg
{
  /**
   * Address: 0x00B50FD8 (FUN_00B50FD8)
   *
   * HRESULT
   *
   * What it does:
   * Maps DirectX/COM HRESULT values to the engine's static diagnostic text
   * table, returning "n/a" when no mapping exists.
   */
const char* __stdcall D3DErrorToString(const long a1)
{
  const char *result; // eax

  if ( a1 > -2005532092 )
  {
    if ( a1 <= -2005532042 )
    {
      if ( a1 == -2005532042 )
        return "An attempt was made to allocate non-local video memory from a device that does not support non-local video memory.";
      switch ( a1 )
      {
        case -2005532091:
          result = "An attempt was made to set the cooperative level when it was already set to exclusive.";
          break;
        case -2005532090:
          result = "An attempt has been made to flip a surface that is not flippable.";
          break;
        case -2005532089:
          result = "Can't duplicate primary & 3D surfaces, or surfaces that are implicitly created.";
          break;
        case -2005532088:
          result = "Surface was not locked.  An attempt to unlock a surface that was not locked at all, or by this proces"
                   "s, has been attempted.";
          break;
        case -2005532087:
          result = "Windows can not create any more DCs, or a DC was requested for a paltte-indexed surface when the surf"
                   "ace had no palette AND the display mode was not palette-indexed (in this case DirectDraw cannot selec"
                   "t a proper palette into the DC)";
          break;
        case -2005532086:
          result = "No DC was ever created for this surface.";
          break;
        case -2005532085:
          result = "This surface can not be restored because it was created in a different mode.";
          break;
        case -2005532084:
          result = "This surface can not be restored because it is an implicitly created surface.";
          break;
        case -2005532083:
          result = "The surface being used is not a palette-based surface";
          break;
        case -2005532082:
          result = "The display is currently in an unsupported mode";
          break;
        case -2005532081:
          result = "Operation could not be carried out because there is no mip-map texture mapping hardware present or available.";
          break;
        case -2005532080:
          result = "The requested action could not be performed because the surface was of the wrong type.";
          break;
        case -2005532072:
          result = "Device does not support optimized surfaces, therefore no video memory optimized surfaces";
          break;
        case -2005532071:
          result = "Surface is an optimized surface, but has not yet been allocated any memory";
          break;
        case -2005532070:
          result = "Attempt was made to create or set a device window without first setting the focus window";
          break;
        case -2005532069:
          result = "Attempt was made to set a palette on a mipmap sublevel";
          break;
        case -2005532052:
          result = "A DC has already been returned for this surface. Only one DC can be retrieved per surface.";
          break;
        default:
          return "n/a";
      }
      return result;
    }
    if ( a1 > -2005396959 )
    {
      if ( a1 <= -2005336063 )
      {
        if ( a1 == -2005336063 )
          return "There are too many unique state objects.";
        switch ( a1 )
        {
          case -2005396958:
            result = "The file contains an invalid parameter control track.";
            break;
          case -2005396957:
            result = "A script written in AudioVBScript could not be read because it contained a statement that is not al"
                     "lowed by the AudioVBScript language.";
            break;
          case -2005396956:
            result = "A script routine written in AudioVBScript failed because an invalid operation occurred.  For exampl"
                     "e, adding the number 3 to a segment object would produce this error.  So would attempting to call a"
                     " routine that doesn't exist.";
            break;
          case -2005396955:
            result = "A script routine written in AudioVBScript failed because a function outside of a script failed to c"
                     "omplete. For example, a call to PlaySegment that fails to play because of low memory would return this error.";
            break;
          case -2005396954:
            result = "The Performance has set up some PChannels using the AssignPChannel command, which makes it not capa"
                     "ble of supporting audio paths.";
            break;
          case -2005396953:
            result = "This is the inverse of the previous error. The Performance has set up some audio paths, which makes"
                     " is incompatible with the calls to allocate pchannels, etc. ";
            break;
          case -2005396952:
            result = "A segment or song was asked for its embedded audio path configuration, but there isn't any. ";
            break;
          case -2005396951:
            result = "An audiopath is inactive, perhaps because closedown was called.";
            break;
          case -2005396950:
            result = "An audiopath failed to create because a requested buffer could not be created.";
            break;
          case -2005396949:
            result = "An audiopath could not be used for playback because it lacked port assignments.";
            break;
          case -2005396948:
            result = "Attempt was made to play segment in audiopath mode and there was no audiopath.";
            break;
          case -2005396947:
            result = "Invalid data was found in a RIFF file chunk.";
            break;
          case -2005396946:
            result = "Attempt was made to create an audiopath that sends to a global effects buffer which did not exist.";
            break;
          case -2005396945:
            result = "The file does not contain a valid container object.";
            break;
          default:
            return "n/a";
        }
        return result;
      }
      if ( a1 <= -931722305 )
      {
        if ( a1 == -931722305 )
          return "Z buffer has not been created";
        if ( a1 > -1966669805 )
        {
          if ( a1 > -1072898029 )
          {
            if ( a1 > -1072898010 )
            {
              if ( a1 <= -931722310 )
              {
                switch ( a1 )
                {
                  case -931722310:
                    return "The Device Index passed in is invalid";
                  case -1072897501:
                    return "The validate method failed because the document does not contain exactly one root node.";
                  case -1072897500:
                    return "The validate method failed because a DTD or schema was not specified in the document.";
                  case -931722312:
                    return "Out of memory";
                  case -931722311:
                    return "A NULL pointer was passed as a parameter";
                }
                return "n/a";
              }
              switch ( a1 )
              {
                case -931722309:
                  return "DirectDraw has not been created";
                case -931722308:
                  return "Direct3D has not been created";
                case -931722307:
                  return "Direct3D device has not been created";
                default:
                  return "Primary surface has not been created";
              }
            }
            else if ( a1 == -1072898010 )
            {
              return "Expecting: %1.";
            }
            else
            {
              switch ( a1 )
              {
                case -1072898028:
                  result = "Element content is invalid according to the DTD or schema.";
                  break;
                case -1072898027:
                  result = "The attribute '%1' on this element is not defined in the DTD or schema.";
                  break;
                case -1072898026:
                  result = "Attribute '%1' has a value that does not match the fixed value defined in the DTD or schema.";
                  break;
                case -1072898025:
                  result = "Attribute '%1' has an invalid value according to the DTD or schema.";
                  break;
                case -1072898024:
                  result = "Text is not allowed in this element according to the DTD or schema.";
                  break;
                case -1072898023:
                  result = "An attribute declaration cannot contain multiple fixed values: '%1'.";
                  break;
                case -1072898020:
                  result = "Reference to undeclared element: '%1'.";
                  break;
                case -1072898018:
                  result = "Attribute '%1' must be a #FIXED attribute.";
                  break;
                case -1072898016:
                  result = "Required attribute '%1' is missing.";
                  break;
                default:
                  return "n/a";
              }
            }
          }
          else
          {
            if ( a1 == -1072898029 )
              return "The name of the top-most element must match the name of the DOCTYPE declaration.";
            if ( a1 <= -1072898046 )
            {
              if ( a1 == -1072898046 )
                return "Reference to undefined entity '%1'.";
              if ( a1 > -1966669566 )
              {
                switch ( a1 )
                {
                  case -1966669565:
                    return "Missing an RPC curve.";
                  case -1966669564:
                    return "Missing data for an audition command.";
                  case -1966669563:
                    return "Unknown command.";
                  case -1966669562:
                    return "Missing a DSP parameter.";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -1966669566:
                    return "Missing a soundbank.";
                  case -1966669804:
                    return "Unable to select a variation.";
                  case -1966669803:
                    return "There can be only one audition engine.";
                  case -1966669802:
                    return "The wavebank is not prepared.";
                  case -1966669567:
                    return "Error writing a file during auditioning.";
                }
              }
              return "n/a";
            }
            switch ( a1 )
            {
              case -1072898045:
                result = "Entity '%1' contains an infinite entity reference loop.";
                break;
              case -1072898044:
                result = "Cannot use the NDATA keyword in a parameter entity declaration.";
                break;
              case -1072898043:
                result = "Cannot use a general parsed entity '%1' as the value for attribute '%2'.";
                break;
              case -1072898042:
                result = "Cannot use unparsed entity '%1' in an entity reference.";
                break;
              case -1072898041:
                result = "Cannot reference an external general parsed entity '%1' in an attribute value.";
                break;
              case -1072898035:
                result = "The element '%1' is used but not declared in the DTD or schema.";
                break;
              case -1072898034:
                result = "The attribute '%1' references the ID '%2', which is not defined in the document.";
                break;
              case -1072898031:
                result = "Element cannot be empty according to the DTD or schema.";
                break;
              case -1072898030:
                result = "Element content is incomplete according to the DTD or schema.";
                break;
              default:
                return "n/a";
            }
          }
        }
        else
        {
          if ( a1 == -1966669805 )
            return "No wavebank exists for desired operation.";
          if ( a1 > -2003435509 )
          {
            if ( a1 > -1966669815 )
            {
              switch ( a1 )
              {
                case -1966669814:
                  result = "Invalid variable index.";
                  break;
                case -1966669813:
                  result = "Invalid category.";
                  break;
                case -1966669812:
                  result = "Invalid cue index.";
                  break;
                case -1966669811:
                  result = "Invalid wave index.";
                  break;
                case -1966669810:
                  result = "Invalid track index.";
                  break;
                case -1966669809:
                  result = "Invalid sound offset or index.";
                  break;
                case -1966669808:
                  result = "Error reading a file.";
                  break;
                case -1966669807:
                  result = "Unknown event type.";
                  break;
                case -1966669806:
                  result = "Invalid call of method of function from callback.";
                  break;
                default:
                  return "n/a";
              }
            }
            else
            {
              if ( a1 == -1966669815 )
                return "Global Settings not loaded.";
              if ( a1 <= -1966669820 )
              {
                switch ( a1 )
                {
                  case -1966669820:
                    return "No notification callback.";
                  case -2003435508:
                    return "An audio device became unusable (unplugged, etc).";
                  case -1966669823:
                    return "The engine is already initialized.";
                  case -1966669822:
                    return "The engine has not been initialized.";
                  case -1966669821:
                    return "The engine has expired (demo or pre-release version).";
                }
                return "n/a";
              }
              switch ( a1 )
              {
                case -1966669819:
                  return "Notification already registered.";
                case -1966669818:
                  return "Invalid usage.";
                case -1966669817:
                  return "Invalid data.";
                default:
                  return "Fail to play due to instance limit.";
              }
            }
          }
          else
          {
            if ( a1 == -2003435509 )
              return "Failed to instantiate an effect.";
            if ( a1 <= -2003435519 )
            {
              if ( a1 == -2003435519 )
                return "Method cannot be called before IXAudio2::Initialize.";
              if ( a1 > -2005270522 )
              {
                switch ( a1 )
                {
                  case -2005270521:
                    return "Device reset.";
                  case -2005270518:
                    return "Was still drawing.";
                  case -2005270496:
                    return "An internal driver error occurred.";
                  case -2005270495:
                    return "The application attempted to perform an operation on an DXGI output that is only legal after "
                           "the output has been claimed for exclusive owenership.";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -2005270522:
                    return "Device hung.";
                  case -2005270527:
                    return "The application has made an erroneous API call that it had enough information to avoid. This "
                           "error is intended to denote that the application should be altered to avoid the error. Use of"
                           " the debug version of the DXGI.DLL will provide run-time debug output with further information.";
                  case -2005270526:
                    return "The item requested was not found. For GetPrivateData calls, this means that the specified GUI"
                           "D had not been previously associated with the object.";
                  case -2005270525:
                    return "The specified size of the destination buffer is too small to hold the requested data.";
                  case -2005270524:
                    return "Unsupported.";
                  case -2005270523:
                    return "Device removed.";
                }
              }
              return "n/a";
            }
            switch ( a1 )
            {
              case -2003435518:
                result = "IXAudio2::Initialize was called redundantly.";
                break;
              case -2003435517:
                result = "One of the given arguments was invalid.";
                break;
              case -2003435516:
                result = "One of the flags was invalid for this method.";
                break;
              case -2003435515:
                result = "A required pointer argument was NULL.";
                break;
              case -2003435514:
                result = "An given index was out of the valid range.";
                break;
              case -2003435513:
                result = "The method call is currently invalid.";
                break;
              case -2003435512:
                result = "Object cannot be destroyed because it is still in use.";
                break;
              case -2003435511:
                result = "Requested operation is unsupported on this platform/device.";
                break;
              case -2003435510:
                result = "The XMA hardware suffered an unrecoverable error.";
                break;
              default:
                return "n/a";
            }
          }
        }
        return result;
      }
      if ( a1 <= 0 )
      {
        if ( !a1 )
          return "The function completed successfully";
        switch ( a1 )
        {
          case -931722304:
            result = "Backbuffer has not been created";
            break;
          case -931722303:
            result = "Failed to update caps database after changing display mode";
            break;
          case -931722302:
            result = "Could not create Z buffer";
            break;
          case -931722301:
            result = "Display mode is not valid";
            break;
          case -931722300:
            result = "One or more of the parameters passed is invalid";
            break;
          case -931722299:
            result = "D3DX failed to initialize itself";
            break;
          case -931722298:
            result = "D3DX failed to start up";
            break;
          case -931722297:
            result = "D3DXInitialize() must be called first";
            break;
          case -931722296:
            result = "D3DX is not initialized yet";
            break;
          case -931722295:
            result = "Failed to render text to the surface";
            break;
          case -931722294:
            result = "Bad D3DX context";
            break;
          case -931722293:
            result = "The requested device capabilities are not supported";
            break;
          case -931722292:
            result = "The image file format is unrecognized";
            break;
          case -931722291:
            result = "The image file loading library error";
            break;
          case -931722290:
            result = "Could not obtain device caps";
            break;
          case -931722289:
            result = "Resize does not work for full-screen";
            break;
          case -931722288:
            result = "Resize does not work for non-windowed contexts";
            break;
          case -931722287:
            result = "Front buffer already exists";
            break;
          case -931722286:
            result = "The app is using the primary in full-screen mode";
            break;
          case -931722285:
            result = "Could not get device context";
            break;
          case -931722284:
            result = "Could not bitBlt";
            break;
          case -931722283:
            result = "There is no surface backing up this texture";
            break;
          case -931722282:
            result = "There is no such miplevel for this surface";
            break;
          case -931722281:
            result = "The surface is not paletted";
            break;
          case -931722280:
            result = "An error occured while enumerating surface formats";
            break;
          case -931722279:
            result = "D3DX only supports color depths of 16 bit or greater";
            break;
          case -931722278:
            result = "The file format is invalid";
            break;
          case -931722277:
            result = "No suitable match found";
            break;
          default:
            return "n/a";
        }
        return result;
      }
      if ( a1 <= 262147 )
      {
        if ( a1 == 262147 )
          return "End of stream. Sample not updated.";
        switch ( a1 )
        {
          case 1:
            result = "Call successful, but returned FALSE";
            break;
          case 2:
            return "The system cannot find the file specified.";
          case 3:
            return "The system cannot find the path specified.";
          case 4:
            return "The system cannot open the file.";
          case 5:
            result = "Access is denied.";
            break;
          case 6:
            result = "The handle is invalid.";
            break;
          case 8:
            return "Not enough storage is available to process this command.";
          case 9:
            return "The storage control block address is invalid.";
          case 10:
            return "The environment is incorrect.";
          case 11:
            return "An attempt was made to load a program with an incorrect format.";
          case 14:
            result = "The system cannot find the drive specified.";
            break;
          default:
            return "n/a";
        }
        return result;
      }
      if ( a1 <= 262797 )
      {
        if ( a1 == 262797 )
          return "The seek into the movie was not frame accurate.";
        if ( a1 > 262744 )
        {
          if ( a1 > 262760 )
          {
            switch ( a1 )
            {
              case 262768:
                return "The stop time for the sample was not set.";
              case 262782:
                return "There was no preview pin available, so the capture pin output is being split to provide both capt"
                       "ure and preview.";
              case 262784:
                return "The current title was not a sequential set of chapters (PGC), and the returned timing information"
                       " might not be continuous.";
              case 262796:
                return "The audio stream did not contain sufficient information to determine the contents of each channel.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case 262760:
                return "The graph can't be cued because of lack of or corrupt data.";
              case 262746:
                return "Cannot play back the video stream: format 'RPZA' is not supported.";
              case 262752:
                return "The value returned had to be estimated.  It's accuracy can not be guaranteed.";
              case 262755:
                return "This success code is reserved for internal purposes within ActiveMovie.";
              case 262759:
                return "The stream has been turned off.";
            }
          }
        }
        else
        {
          if ( a1 == 262744 )
            return "Cannot play back the audio stream: no audio hardware is available.";
          if ( a1 > 262725 )
          {
            switch ( a1 )
            {
              case 262726:
                return "Some connections have failed and have been deferred.";
              case 262736:
                return "The resource specified is no longer needed.";
              case 262740:
                return "A connection could not be made with the media type in the persistent graph, but has been made wit"
                       "h a negotiated media type.";
              case 262743:
                return "Cannot play back the video stream: no suitable decompressor could be found.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case 262725:
                return "The file contained some property settings that were not used.";
              case 262403:
                return "The end of the list has been reached.";
              case 262701:
                return "An attempt to add a filter with a duplicate name succeeded with a modified name.";
              case 262711:
                return "The state transition has not completed.";
              case 262722:
                return "Some of the streams in this movie are in an unsupported format.";
            }
          }
        }
        return "n/a";
      }
      if ( a1 <= 142086658 )
      {
        if ( a1 == 142086658 )
          return "Return value from IDirectMusicTrack::Play() which indicates to the segment that the track has no more d"
                 "ata after mtEnd.";
        if ( a1 > 142082058 )
        {
          switch ( a1 )
          {
            case 142086289:
              return "The object could only load partially. This can happen if some components are not registered properl"
                     "y, such as embedded tracks and tools. This can also happen if some content is missing. For example,"
                     " if a segment uses a DLS collection that is not in the loader's current search directory.";
            case 142086290:
              return "Return value from IDirectMusicBand::Download() which indicates that some of the instruments safely "
                     "downloaded, but others failed. This usually occurs when some instruments are on PChannels not suppo"
                     "rted by the performance or port.";
            case 142086656:
              return "Return value from IDirectMusicTool::ProcessPMsg() which indicates to the performance that it should"
                     " cue the PMsg again automatically.";
            case 142086657:
              return "Return value from IDirectMusicTool::ProcessPMsg() which indicates to the performance that it should"
                     " free the PMsg automatically.";
          }
        }
        else
        {
          switch ( a1 )
          {
            case 142082058:
              return "The call succeeded, but we had to substitute the 3D algorithm";
            case 1376261:
              return "Full duplex";
            case 1376266:
              return "Half duplex";
            case 1376272:
              return "Pending";
            case 141953135:
              return "The call succeeded but there won't be any mipmaps generated";
          }
        }
        return "n/a";
      }
      if ( a1 <= 142086676 )
      {
        switch ( a1 )
        {
          case 142086676:
            return "Returned from IDirectMusicPerformance::MIDIToMusic(),  and IDirectMusicPerformance::MusicToMIDI(), th"
                   "is indicates  that the note conversion generated a note value that is above 127, so it has been bumpe"
                   "d down one or more octaves to be in the proper MIDI range of 0 through 127.  Note that this is valid "
                   "for MIDIToMusic() when using play modes DMUS_PLAYMODE_FIXEDTOCHORD and DMUS_PLAYMODE_FIXEDTOKEY, both"
                   " of which store MIDI values in wMusicValue. With MusicToMIDI(), it is valid for all play modes. Ofcou"
                   "rse, DMUS_PLAYMODE_FIXED will never return this success code.";
          case 142086672:
            return "Returned string has been truncated to fit the buffer size.";
          case 142086673:
            return "Returned from IDirectMusicGraph::StampPMsg(), this indicates that the PMsg is already stamped with th"
                   "e last tool in the graph. The returned PMsg's tool pointer is now NULL.";
          case 142086674:
            return "Returned from IDirectMusicPerformance::MusicToMIDI(), this indicates  that no note has been calculate"
                   "d because the music value has the note  at a position higher than the top note of the chord. This app"
                   "lies only to DMUS_PLAYMODE_NORMALCHORD play mode. This success code indicates that the caller should "
                   "not do anything with the note. It is not meant to be played against this chord.";
          case 142086675:
            return "Returned from IDirectMusicPerformance::MIDIToMusic(),  and IDirectMusicPerformance::MusicToMIDI(), th"
                   "is indicates  that the note conversion generated a note value that is below 0,  so it has been bumped"
                   " up one or more octaves to be in the proper MIDI range of 0 through 127.  Note that this is valid for"
                   " MIDIToMusic() when using play modes DMUS_PLAYMODE_FIXEDTOCHORD and DMUS_PLAYMODE_FIXEDTOKEY, both of"
                   " which store MIDI values in wMusicValue. With MusicToMIDI(), it is valid for all play modes. Ofcourse"
                   ", DMUS_PLAYMODE_FIXED will never return this success code.";
        }
        return "n/a";
      }
      switch ( a1 )
      {
        case 142086677:
          return "Although the audio output from the port will be routed to the same device as the given DirectSound buff"
                 "er, buffer controls such as pan and volume will not affect the output.";
        case 142086678:
          return "The requested operation was not performed because during CollectGarbage the loader determined that the "
                 "object had been released.";
        case 142213121:
          return "The target window or output has been occluded. The application should suspend rendering operations if possible.";
      }
      return "n/a";
    }
    if ( a1 == -2005396959 )
      return "The file contains an invalid lyrics track.";
    if ( a1 > -2005397240 )
    {
      switch ( a1 )
      {
        case -2005397239:
          result = "Wave chunks in DLS collection file are at incorrect offsets.";
          break;
        case -2005397231:
          result = "Second attempt to load a DLS collection that is currently open. ";
          break;
        case -2005397229:
          result = "Error reading wave data from DLS collection. Indicates bad file.";
          break;
        case -2005397228:
          result = "There is no instrument in the collection that matches patch number.";
          break;
        case -2005397227:
          result = "The IStream* doesn't support Seek().";
          break;
        case -2005397226:
          result = "The IStream* doesn't support Write().";
          break;
        case -2005397225:
          result = "The RIFF parser doesn't contain a required chunk while parsing file.";
          break;
        case -2005397223:
          result = "Invalid download id was used in the process of creating a download buffer.";
          break;
        case -2005397216:
          result = "Tried to unload an object that was not downloaded or previously unloaded.";
          break;
        case -2005397215:
          result = "Buffer was already downloaded to synth.";
          break;
        case -2005397214:
          result = "The specified property item was not recognized by the target object.";
          break;
        case -2005397213:
          result = "The specified property item may not be set on the target object.";
          break;
        case -2005397212:
          result = "* The specified property item may not be retrieved from the target object.";
          break;
        case -2005397211:
          result = "Wave chunk has more than one interleaved channel. DLS format requires MONO.";
          break;
        case -2005397210:
          result = "Invalid articulation chunk in DLS collection.";
          break;
        case -2005397209:
          result = "Invalid instrument chunk in DLS collection.";
          break;
        case -2005397208:
          result = "Wavelink chunk in DLS collection points to invalid wave.";
          break;
        case -2005397207:
          result = "Articulation missing from instrument in DLS collection.";
          break;
        case -2005397206:
          result = "Downoaded DLS wave is not in PCM format. ";
          break;
        case -2005397205:
          result = "Bad wave chunk in DLS collection";
          break;
        case -2005397204:
          result = "Offset Table for download buffer has errors. ";
          break;
        case -2005397203:
          result = "Attempted to download unknown data type.";
          break;
        case -2005397202:
          result = "The operation could not be completed because no sink was connected to the synthesizer.";
          break;
        case -2005397201:
          result = "An attempt was made to open the software synthesizer while it was already  open.";
          break;
        case -2005397200:
          result = "An attempt was made to close the software synthesizer while it was already  open.";
          break;
        case -2005397199:
          result = "The operation could not be completed because the software synth has not  yet been fully configured.";
          break;
        case -2005397198:
          result = "The operation cannot be carried out while the synthesizer is active.";
          break;
        case -2005397197:
          result = "An error occurred while attempting to read from the IStream* object.";
          break;
        case -2005397196:
          result = "The operation cannot be performed because the final instance of the DirectMusic object was released. "
                   "Ports cannot be used after final  release of the DirectMusic object.";
          break;
        case -2005397195:
          result = "There was no data in the referenced buffer.";
          break;
        case -2005397194:
          result = "There is insufficient space to insert the given event into the buffer.";
          break;
        case -2005397193:
          result = "The given operation could not be carried out because the port is a capture port.";
          break;
        case -2005397192:
          result = "The given operation could not be carried out because the port is a render port.";
          break;
        case -2005397191:
          result = "The port could not be created because no DirectSound has been specified. Specify a DirectSound interf"
                   "ace via the IDirectMusic::SetDirectSound method; pass NULL to have DirectMusic manage usage of DirectSound.";
          break;
        case -2005397190:
          result = "The operation cannot be carried out while the port is active.";
          break;
        case -2005397189:
          result = "Invalid DirectSound buffer was handed to port. ";
          break;
        case -2005397188:
          result = "Invalid buffer format was handed to the synth sink.";
          break;
        case -2005397187:
          result = "The operation cannot be carried out while the synthesizer is inactive.";
          break;
        case -2005397186:
          result = "IDirectMusic::SetDirectSound has already been called. It may not be changed while in use.";
          break;
        case -2005397185:
          result = "The given event is invalid (either it is not a valid MIDI message or it makes use of running status)."
                   " The event cannot be packed into the buffer.";
          break;
        case -2005397168:
          result = "The IStream* object does not contain data supported by the loading object.";
          break;
        case -2005397167:
          result = "The object has already been initialized.";
          break;
        case -2005397166:
          result = "The file does not contain a valid band.";
          break;
        case -2005397163:
          result = "The IStream* object's data does not have a track header as the first chunk, and therefore can not be "
                   "read by the segment object.";
          break;
        case -2005397162:
          result = "The IStream* object's data does not have a tool header as the first chunk, and therefore can not be r"
                   "ead by the graph object.";
          break;
        case -2005397161:
          result = "The IStream* object's data contains an invalid track header (ckid is 0 and fccType is NULL,) and ther"
                   "efore can not be read by the segment object.";
          break;
        case -2005397160:
          result = "The IStream* object's data contains an invalid tool header (ckid is 0 and fccType is NULL,) and there"
                   "fore can not be read by the graph object.";
          break;
        case -2005397159:
          result = "The graph object was unable to load all tools from the IStream* object data. This may be due to error"
                   "s in the stream, or the tools being incorrectly registered on the client.";
          break;
        case -2005397152:
          result = "The segment object was unable to load all tracks from the IStream* object data. This may be due to er"
                   "rors in the stream, or the tracks being incorrectly registered on the client.";
          break;
        case -2005397151:
          result = "The object requested was not found (numerically equal to DMUS_E_NOT_FOUND)";
          break;
        case -2005397150:
          result = "A required object is not initialized or failed to initialize.";
          break;
        case -2005397149:
          result = "The requested parameter type is currently disabled. Parameter types may be enabled and disabled by ce"
                   "rtain calls to SetParam().";
          break;
        case -2005397148:
          result = "The requested parameter type is not supported on the object.";
          break;
        case -2005397147:
          result = "The time is in the past, and the operation can not succeed.";
          break;
        case -2005397146:
          result = "The requested track is not contained by the segment.";
          break;
        case -2005397145:
          result = "The track does not support clock time playback or getparam.";
          break;
        case -2005397136:
          result = "There is no master clock in the performance. Be sure to call IDirectMusicPerformance::Init().";
          break;
        case -2005397120:
          result = "The class id field is required and missing in the DMUS_OBJECTDESC.";
          break;
        case -2005397119:
          result = "The requested file path is invalid.";
          break;
        case -2005397118:
          result = "File open failed - either file doesn't exist or is locked.";
          break;
        case -2005397117:
          result = "Search data type is not supported.";
          break;
        case -2005397116:
          result = "Unable to find or create object.";
          break;
        case -2005397115:
          result = "Object was not found.";
          break;
        case -2005397114:
          result = "The file name is missing from the DMUS_OBJECTDESC.";
          break;
        case -2005396992:
          result = "The file requested is not a valid file.";
          break;
        case -2005396991:
          result = "The tool is already contained in the graph. Create a new instance.";
          break;
        case -2005396990:
          result = "Value is out of range, for instance the requested length is longer than the segment.";
          break;
        case -2005396989:
          result = "Segment initialization failed, most likely due to a critical memory situation.";
          break;
        case -2005396988:
          result = "The DMUS_PMSG has already been sent to the performance object via IDirectMusicPerformance::SendPMsg().";
          break;
        case -2005396987:
          result = "The DMUS_PMSG was either not allocated by the performance via IDirectMusicPerformance::AllocPMsg(), o"
                   "r it was already freed via IDirectMusicPerformance::FreePMsg().";
          break;
        case -2005396986:
          result = "The default system port could not be opened.";
          break;
        case -2005396985:
          result = "A call to MIDIToMusic() or MusicToMIDI() resulted in an error because the requested conversion could "
                   "not happen. This usually occurs when the provided DMUS_CHORD_KEY structure has an invalid chord or scale pattern.";
          break;
        case -2005396976:
          result = "DMUS_E_DESCEND_CHUNK_FAIL is returned when the end of the file  was reached before the desired chunk was found.";
          break;
        case -2005396975:
          result = "An attempt to use this object failed because it first needs to be loaded.";
          break;
        case -2005396973:
          result = "The activeX scripting engine for the script's language is not compatible with DirectMusic.";
          break;
        case -2005396972:
          result = "A varient was used that had a type that is not supported by DirectMusic.";
          break;
        case -2005396971:
          result = "An error was encountered while parsing or executing the script. The pErrorInfo parameter (if supplied"
                   ") was filled with information about the error.";
          break;
        case -2005396970:
          result = "Loading of oleaut32.dll failed.  VBScript and other activeX scripting languages require use of oleaut"
                   "32.dll.  On platforms where oleaut32.dll is not present, only the DirectMusicScript language, which d"
                   "oesn't require oleaut32.dll can be used.";
          break;
        case -2005396969:
          result = "An error occured while parsing a script loaded using LoadScript.  The script that was loaded contains an error.";
          break;
        case -2005396968:
          result = "The script file is invalid.";
          break;
        case -2005396967:
          result = "The file contains an invalid script track.";
          break;
        case -2005396966:
          result = "The script does not contain a variable with the specified name.";
          break;
        case -2005396965:
          result = "The script does not contain a routine with the specified name.";
          break;
        case -2005396964:
          result = "Scripts variables for content referenced or embedded in a script cannot be set.";
          break;
        case -2005396963:
          result = "Attempt was made to set a script's variable by reference to a value that was not an object type.";
          break;
        case -2005396962:
          result = "Attempt was made to set a script's variable by value to an object that does not support a default value property.";
          break;
        case -2005396960:
          result = "The file contains an invalid segment trigger track.";
          break;
        default:
          return "n/a";
      }
      return result;
    }
    if ( a1 == -2005397240 )
      return "Error parsing DLS collection. File is corrupt.";
    if ( a1 <= -2005530595 )
    {
      if ( a1 == -2005530595 )
        return "Too many operations";
      if ( a1 > -2005531771 )
      {
        if ( a1 > -2005530600 )
        {
          switch ( a1 )
          {
            case -2005530599:
              return "Unsupported color operation";
            case -2005530598:
              return "Unsupported color arg";
            case -2005530597:
              return "Unsupported alpha operation";
            default:
              return "Unsupported alpha arg";
          }
        }
        else if ( a1 == -2005530600 )
        {
          return "Wrong texture format";
        }
        else
        {
          switch ( a1 )
          {
            case -2005531770:
              result = "Bad type";
              break;
            case -2005531769:
              return "Not found";
            case -2005531768:
              result = "Not done yet";
              break;
            case -2005531767:
              result = "File not found";
              break;
            case -2005531766:
              result = "Resource not found";
              break;
            case -2005531765:
              result = "Bad resource";
              break;
            case -2005531764:
              result = "Bad file type";
              break;
            case -2005531763:
              result = "Bad file version";
              break;
            case -2005531762:
              result = "Bad file float size";
              break;
            case -2005531761:
              result = "Bad file";
              break;
            case -2005531760:
              result = "Parse error";
              break;
            case -2005531759:
LABEL_679:
              result = "Bad array size";
              break;
            case -2005531758:
LABEL_680:
              result = "Bad data reference";
              break;
            case -2005531757:
LABEL_681:
              result = "No more objects";
              break;
            case -2005531756:
LABEL_682:
              result = "No more data";
              break;
            case -2005531755:
LABEL_683:
              result = "Bad cache file";
              break;
            default:
              return "n/a";
          }
        }
      }
      else
      {
        if ( a1 == -2005531771 )
          return "Bad value";
        if ( a1 <= -2005531973 )
        {
          if ( a1 == -2005531973 )
            return "Surfaces created by one direct draw device cannot be used directly by another direct draw device.";
          if ( a1 > -2005531980 )
          {
            switch ( a1 )
            {
              case -2005531979:
                return "The mode test has switched to a new mode.";
              case -2005531978:
                return "D3D has not yet been initialized.";
              case -2005531977:
                return "The video port is not active";
              case -2005531976:
                return "The monitor does not have EDID data.";
              case -2005531975:
                return "The driver does not enumerate display mode refresh rates.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2005531980:
                return "The mode test has finished executing.";
              case -2005532032:
                return "The attempt to page lock a surface failed.";
              case -2005532012:
                return "The attempt to page unlock a surface failed.";
              case -2005531992:
                return "An attempt was made to page unlock a surface with no outstanding page locks.";
              case -2005531982:
                return "There is more data available than the specified buffer size could hold";
              case -2005531981:
                return "The data has expired and is therefore no longer valid.";
            }
          }
          return "n/a";
        }
        if ( a1 == -2005531772 )
        {
          return "Bad object";
        }
        else
        {
          switch ( a1 )
          {
            case -2005531804:
              goto LABEL_679;
            case -2005531803:
              goto LABEL_680;
            case -2005531802:
              result = "Internal error";
              break;
            case -2005531801:
              goto LABEL_681;
            case -2005531800:
              result = "Bad intrinsics";
              break;
            case -2005531799:
              result = "No more stream handles";
              break;
            case -2005531798:
              goto LABEL_682;
            case -2005531797:
              goto LABEL_683;
            case -2005531796:
              result = "No internet";
              break;
            default:
              return "n/a";
          }
        }
      }
      return result;
    }
    if ( a1 <= -2005529765 )
    {
      if ( a1 == -2005529765 )
        return "Duplicate named fragment";
      if ( a1 <= -2005530518 )
      {
        if ( a1 == -2005530518 )
          return "Not available";
        if ( a1 > -2005530585 )
        {
          switch ( a1 )
          {
            case -2005530522:
              return "Not found";
            case -2005530521:
              return "More data";
            case -2005530520:
              return "Device lost";
            case -2005530519:
              return "Device not reset";
          }
        }
        else
        {
          switch ( a1 )
          {
            case -2005530585:
              return "Driver internal error";
            case -2005530594:
              return "Conflicting texture filter";
            case -2005530593:
              return "Unsupported factor value";
            case -2005530591:
              return "Conflicting render state";
            case -2005530590:
              return "Unsupported texture filter";
            case -2005530586:
              return "Conflicting texture palette";
          }
        }
        return "n/a";
      }
      if ( a1 <= -2005529770 )
      {
        switch ( a1 )
        {
          case -2005529770:
            return "Cannot attr sort";
          case -2005530517:
            return "Invalid device";
          case -2005530516:
            return "Invalid call";
          case -2005530515:
            return "Driver invalid call";
          case -2005529772:
            return "Can not modify index buffer";
          case -2005529771:
            return "Invalid mesh";
        }
        return "n/a";
      }
      switch ( a1 )
      {
        case -2005529769:
          return "Skinning not supported";
        case -2005529768:
          return "Too many influences";
        case -2005529767:
          return "Invalid data";
      }
      return "Loaded mesh has no data";
    }
    if ( a1 > -2005401430 )
    {
      if ( a1 > -2005397246 )
      {
        switch ( a1 )
        {
          case -2005397245:
            return "The requested device is already in use (possibly by a non-DirectMusic client) and cannot be opened again.";
          case -2005397244:
            return "Buffer is not large enough for requested operation.";
          case -2005397243:
            return "No buffer was prepared for the download data.";
          case -2005397242:
            return "Download failed due to inability to access or create download buffer.";
        }
      }
      else
      {
        switch ( a1 )
        {
          case -2005397246:
            return "The requested operation cannot be performed while there are  instantiated ports in any process in the system.";
          case -2005401420:
            return "Tried to create a DSBCAPS_CTRLFX buffer shorter than DSBSIZE_FX_MIN milliseconds";
          case -2005401410:
            return "Attempt to use DirectSound 8 functionality on an older DirectSound object";
          case -2005401400:
            return "A circular loop of send effects was detected";
          case -2005401390:
            return "The GUID specified in an audiopath file does not match a valid MIXIN buffer";
          case -2005397247:
            return "An unexpected error was returned from a device driver, indicating possible failure of the driver or hardware.";
        }
      }
      return "n/a";
    }
    if ( a1 == -2005401430 )
      return "This object has not been initialized";
    if ( a1 <= -2005401500 )
    {
      switch ( a1 )
      {
        case -2005401500:
          return "The specified WAVE format is not supported";
        case -2005529764:
          return "Can Not remove last item";
        case -2005401590:
          return "The call failed because resources (such as a priority level) were already being used by another caller";
        case -2005401570:
          return "The control (vol, pan, etc.) requested by the caller is not available";
        case -2005401550:
          return "This call is not valid for the current state of this object";
        case -2005401530:
          return "The caller does not have the priority level required for the function to succeed";
      }
      return "n/a";
    }
    if ( a1 == -2005401480 )
      return "No sound driver is available for use";
    if ( a1 != -2005401470 )
    {
      if ( a1 == -2005401450 )
        return "The buffer memory has been lost, and must be restored";
      if ( a1 == -2005401440 )
        return "Another app has a higher priority level, preventing this call from succeeding";
      return "n/a";
    }
    return "This object is already initialized";
  }
  if ( a1 == -2005532092 )
    return "returned when an overlay member is called for a non-overlay surface";
  if ( a1 > -2146107092 )
  {
    if ( a1 > -2146073232 )
    {
      if ( a1 > -2005532342 )
      {
        if ( a1 <= -2005532135 )
        {
          if ( a1 == -2005532135 )
            return "vertical blank is in progress";
          if ( a1 > -2005532242 )
          {
            if ( a1 > -2005532192 )
            {
              switch ( a1 )
              {
                case -2005532182:
                  return "Width requested by DirectDraw is too large.";
                case -2005532162:
                  return "Pixel format requested is unsupported by DirectDraw";
                case -2005532152:
                  return "Bitmask in the pixel format requested is unsupported by DirectDraw";
                case -2005532151:
                  return "The specified stream contains invalid data";
              }
            }
            else
            {
              switch ( a1 )
              {
                case -2005532192:
                  return "Size requested by DirectDraw is too large --  The individual height and width are OK.";
                case -2005532237:
                  return "Access to this surface is being refused because no driver exists which can supply a pointer to "
                         "the surface. This is most likely to happen when attempting to lock the primary surface when no "
                         "DCI provider is present. Will also happen on attempts to lock an optimized surface.";
                case -2005532232:
                  return "Access to Surface refused because Surface is obscured.";
                case -2005532222:
                  return "Access to this surface is being refused because the surface is gone. The DIRECTDRAWSURFACE obje"
                         "ct representing this surface should have Restore called on it.";
                case -2005532212:
                  return "The requested surface is not attached.";
                case -2005532202:
                  return "Height requested by DirectDraw is too large.";
              }
            }
          }
          else
          {
            if ( a1 == -2005532242 )
              return "Access to this surface is being refused because the surface is already locked by another thread.";
            if ( a1 > -2005532290 )
            {
              switch ( a1 )
              {
                case -2005532288:
                  return "Can only have ony color key active at one time for overlays";
                case -2005532285:
                  return "Access to this palette is being refused because the palette is already locked by another thread.";
                case -2005532272:
                  return "No src color key specified for this operation.";
                case -2005532262:
                  return "This surface is already attached to the surface it is being attached to.";
                case -2005532252:
                  return "This surface is already a dependency of the surface it is being made a dependency of.";
              }
            }
            else
            {
              switch ( a1 )
              {
                case -2005532290:
                  return "hardware does not support clipped overlays";
                case -2005532337:
                  return "Operation could not be carried out because there is no hardware support for vertical blank sync"
                         "hronized operations.";
                case -2005532332:
                  return "Operation could not be carried out because there is no hardware support for zbuffer blting.";
                case -2005532322:
                  return "Overlay surfaces could not be z layered based on their BltOrder because the hardware does not s"
                         "upport z layering of overlays.";
                case -2005532312:
                  return "The hardware needed for the requested operation has already been allocated.";
                case -2005532292:
                  return "Out of video memory";
              }
            }
          }
          return "n/a";
        }
        switch ( a1 )
        {
          case -2005532132:
            result = "Was still drawing";
            break;
          case -2005532130:
            result = "The specified surface type requires specification of the COMPLEX flag";
            break;
          case -2005532112:
            result = "Rectangle provided was not horizontally aligned on reqd. boundary";
            break;
          case -2005532111:
            result = "The GUID passed to DirectDrawCreate is not a valid DirectDraw driver identifier.";
            break;
          case -2005532110:
            result = "A DirectDraw object representing this driver has already been created for this process.";
            break;
          case -2005532109:
            result = "A hardware only DirectDraw object creation was attempted but the driver did not support any hardware.";
            break;
          case -2005532108:
            result = "this process already has created a primary surface";
            break;
          case -2005532107:
            result = "software emulation not available.";
            break;
          case -2005532106:
            result = "region passed to Clipper::GetClipList is too small.";
            break;
          case -2005532105:
            result = "an attempt was made to set a clip list for a clipper objec that is already monitoring an hwnd.";
            break;
          case -2005532104:
            result = "No clipper object attached to surface object";
            break;
          case -2005532103:
            result = "Clipper notification requires an HWND or no HWND has previously been set as the CooperativeLevel HWND.";
            break;
          case -2005532102:
            result = "HWND used by DirectDraw CooperativeLevel has been subclassed, this prevents DirectDraw from restoring state.";
            break;
          case -2005532101:
            result = "The CooperativeLevel HWND has already been set. It can not be reset while the process has surfaces "
                     "or palettes created.";
            break;
          case -2005532100:
            result = "No palette object attached to this surface.";
            break;
          case -2005532099:
            result = "No hardware support for 16 or 256 color palettes.";
            break;
          case -2005532098:
            result = "If a clipper object is attached to the source surface passed into a BltFast call.";
            break;
          case -2005532097:
            result = "No blter.";
            break;
          case -2005532096:
            result = "No DirectDraw ROP hardware.";
            break;
          case -2005532095:
            result = "returned when GetOverlayPosition is called on a hidden overlay";
            break;
          case -2005532094:
            result = "returned when GetOverlayPosition is called on a overlay that UpdateOverlay has never been called on"
                     " to establish a destionation.";
            break;
          case -2005532093:
            result = "returned when the position of the overlay on the destionation is no longer legal for that destionation.";
            break;
          default:
            return "n/a";
        }
        return result;
      }
      if ( a1 == -2005532342 )
        return "Operation could not be carried out because there is no texture mapping hardware present or available.";
      if ( a1 > -2005532502 )
      {
        if ( a1 > -2005532432 )
        {
          if ( a1 > -2005532382 )
          {
            switch ( a1 )
            {
              case -2005532362:
                return "Operation could not be carried out because there is no hardware support for stretching";
              case -2005532356:
                return "DirectDrawSurface is not in 4 bit color palette and the requested operation requires 4 bit color palette.";
              case -2005532355:
                return "DirectDrawSurface is not in 4 bit color index palette and the requested operation requires 4 bit "
                       "color index palette.";
              case -2005532352:
                return "DirectDraw Surface is not in 8 bit color mode and the requested operation requires 8 bit color.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2005532382:
                return "Operation could not be carried out because there is no rotation hardware present or available.";
              case -2005532422:
                return "Operation could not be carried out because there is no hardware present or available.";
              case -2005532417:
                return "Requested item was not found";
              case -2005532412:
                return "Operation could not be carried out because there is no overlay hardware present or available.";
              case -2005532402:
                return "Operation could not be carried out because the source and destination rectangles are on the same "
                       "surface and overlap each other.";
              case -2005532392:
                return "Operation could not be carried out because there is no appropriate raster op hardware present or available.";
            }
          }
        }
        else
        {
          if ( a1 == -2005532432 )
            return "There is no GDI present.";
          if ( a1 > -2005532460 )
          {
            switch ( a1 )
            {
              case -2005532457:
                return "Surface doesn't currently have a color key";
              case -2005532452:
                return "Operation could not be carried out because there is no hardware support of the dest color key.";
              case -2005532450:
                return "No DirectDraw support possible with current display driver";
              case -2005532447:
                return "Operation requires the application to have exclusive mode but the application does not have exclusive mode.";
              case -2005532442:
                return "Flipping visible surfaces is not supported.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2005532460:
                return "Create function called without DirectDraw object method SetCooperativeLevel being called.";
              case -2005532492:
                return "Operation could not be carried out because there is no alpha accleration hardware present or available.";
              case -2005532491:
                return "Operation could not be carried out because there is no stereo hardware present or available.";
              case -2005532490:
                return "Operation could not be carried out because there is no hardware present which supports stereo surfaces";
              case -2005532467:
                return "no clip list available";
              case -2005532462:
                return "Operation could not be carried out because there is no color conversion hardware present or available.";
            }
          }
        }
        return "n/a";
      }
      if ( a1 == -2005532502 )
        return "There is no 3D present.";
      if ( a1 > -2005532632 )
      {
        if ( a1 > -2005532552 )
        {
          switch ( a1 )
          {
            case -2005532542:
              return "DirectDraw received a pointer that was an invalid DIRECTDRAW object.";
            case -2005532527:
              return "pixel format was invalid as specified";
            case -2005532522:
              return "Rectangle provided was invalid.";
            case -2005532512:
              return "Operation could not be carried out because one or more surfaces are locked";
          }
        }
        else
        {
          switch ( a1 )
          {
            case -2005532552:
              return "DirectDraw does not support the requested mode";
            case -2005532617:
              return "An exception was encountered while performing the requested operation";
            case -2005532582:
              return "Height of rectangle provided is not a multiple of reqd alignment";
            case -2005532577:
              return "Unable to match primary surface creation request with existing primary surface.";
            case -2005532572:
              return "One or more of the caps bits passed to the callback are incorrect.";
            case -2005532562:
              return "DirectDraw does not support provided Cliplist.";
          }
        }
        return "n/a";
      }
      if ( a1 == -2005532632 )
        return "Support is currently not available.";
      if ( a1 <= -2146073040 )
      {
        switch ( a1 )
        {
          case -2146073040:
            return "Timed out";
          case -2146073216:
            return "Player not in group";
          case -2146073200:
            return "Player not reachable";
          case -2146073088:
            return "Send too large";
          case -2146073072:
            return "Session full";
          case -2146073056:
            return "Table full";
        }
        return "n/a";
      }
      if ( a1 == -2146073024 )
        return "Uninitialized";
      if ( a1 != -2146073008 )
      {
        if ( a1 != -2005532667 )
        {
          if ( a1 == -2005532662 )
            return "This surface can not be attached to the requested surface.";
          if ( a1 == -2005532652 )
            return "This surface can not be detached from the requested surface.";
          return "n/a";
        }
        return "This object is already initialized";
      }
    }
    else
    {
      if ( a1 == -2146073232 )
        return "Player lost";
      if ( a1 > -2146074320 )
      {
        if ( a1 <= -2146073792 )
        {
          if ( a1 != -2146073792 )
          {
            if ( a1 > -2146074064 )
            {
              if ( a1 > -2146073968 )
              {
                switch ( a1 )
                {
                  case -2146073856:
                    return "Invalid application";
                  case -2146073840:
                    return "Invalid command";
                  case -2146073824:
                    return "Invalid device address";
                  case -2146073808:
                    return "Invalid end point";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -2146073968:
                    return "Invalid address format";
                  case -2146074048:
                    return "Group not empty";
                  case -2146074032:
                    return "Hosting";
                  case -2146074016:
                    return "Host rejected connection";
                  case -2146074000:
                    return "Host terminated session";
                  case -2146073984:
                    return "Incomplete address";
                }
              }
              return "n/a";
            }
            if ( a1 != -2146074064 )
            {
              if ( a1 > -2146074240 )
              {
                switch ( a1 )
                {
                  case -2146074235:
                    return "dpnsvr not available";
                  case -2146074224:
                    return "Duplicate command";
                  case -2146074112:
                    return "End point not receiving";
                  case -2146074096:
                    return "Enum query too large";
                  case -2146074080:
                    return "Enum response too large";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -2146074240:
                    return "Does not exist";
                  case -2146074304:
                    return "Cant launch application";
                  case -2146074288:
                    return "Connecting";
                  case -2146074272:
                    return "Connection lost";
                  case -2146074256:
                    return "Conversion";
                  case -2146074251:
                    return "Data too large";
                }
              }
              return "n/a";
            }
            return "Exception";
          }
          return "Invalid flags";
        }
        if ( a1 > -2146073504 )
        {
          if ( a1 > -2146073312 )
          {
            switch ( a1 )
            {
              case -2146073296:
                return "Not host";
              case -2146073280:
                return "Not ready";
              case -2146073264:
                return "Not registered";
              case -2146073248:
                return "Player already in group";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2146073312:
                return "Not allowed";
              case -2146073488:
                return "No caps";
              case -2146073472:
                return "No connection";
              case -2146073456:
                return "No host player";
              case -2146073344:
                return "No more address components";
              case -2146073328:
                return "No response";
            }
          }
          return "n/a";
        }
        if ( a1 == -2146073504 )
          return "Invalid version";
        if ( a1 > -2146073600 )
        {
          if ( a1 == -2146073584 )
            return "Invalid password";
          if ( a1 != -2146073568 )
          {
            switch ( a1 )
            {
              case -2146073552:
                return "Invalid priority";
              case -2146073536:
                return "Invalid string";
              case -2146073520:
                return "Invalid url";
            }
            return "n/a";
          }
          return "Invalid player";
        }
        if ( a1 != -2146073600 )
        {
          if ( a1 != -2146073776 )
          {
            if ( a1 != -2146073760 )
            {
              switch ( a1 )
              {
                case -2146073744:
                  return "Invalid host address";
                case -2146073728:
                  return "Invalid instance";
                case -2146073712:
                  return "Invalid interface";
              }
              return "n/a";
            }
            return "Invalid handle";
          }
          return "Invalid group";
        }
        return "Invalid object";
      }
      if ( a1 == -2146074320 )
        return "Cant create player";
      if ( a1 > -2146107008 )
      {
        if ( a1 <= -2146074576 )
        {
          if ( a1 == -2146074576 )
            return "Aborted";
          switch ( a1 )
          {
            case -2146107005:
              result = "Run setup";
              break;
            case -2146107004:
              result = "Incompatible version";
              break;
            case -2146107001:
              result = "Initialized";
              break;
            case -2146107000:
              result = "No transport";
              break;
            case -2146106999:
              result = "No callback";
              break;
            case -2146106998:
              result = "Transport not init";
              break;
            case -2146106997:
              result = "Transport no session";
              break;
            case -2146106996:
              result = "Transport no player";
              break;
            case -2146106995:
              result = "User back";
              break;
            case -2146106994:
              result = "No rec vol available";
              break;
            case -2146106993:
              result = "Invalid buffer";
              break;
            case -2146106992:
              result = "Locked buffer";
              break;
            default:
              return "n/a";
          }
          return result;
        }
        if ( a1 <= -2146074496 )
        {
          switch ( a1 )
          {
            case -2146074496:
              return "Already initialized";
            case -2146074560:
              return "Addressing";
            case -2146074544:
              return "Already closing";
            case -2146074528:
              return "Already connected";
            case -2146074512:
              return "Already disconnecting";
          }
          return "n/a";
        }
        if ( a1 == -2146074480 )
          return "Already registered";
        if ( a1 != -2146074368 )
        {
          if ( a1 == -2146074352 )
            return "Can not cancel";
          if ( a1 == -2146074336 )
            return "Cant create group";
          return "n/a";
        }
        return "Buffer too small";
      }
      if ( a1 != -2146107008 )
      {
        switch ( a1 )
        {
          case -2146107090:
            result = "No voice session";
            break;
          case -2146107032:
            return "Connection lost";
          case -2146107031:
            result = "Not initialized";
            break;
          case -2146107030:
            result = "Connected";
            break;
          case -2146107029:
            result = "Not connected";
            break;
          case -2146107026:
            result = "Connect aborting";
            break;
          case -2146107025:
            return "Not allowed";
          case -2146107024:
            result = "Invalid target";
            break;
          case -2146107023:
            result = "Transport not host";
            break;
          case -2146107022:
            result = "Compression not supported";
            break;
          case -2146107021:
            result = "Already pending";
            break;
          case -2146107020:
            result = "Sound init failure";
            break;
          case -2146107019:
            result = "Time out";
            break;
          case -2146107018:
            result = "Connect aborted";
            break;
          case -2146107017:
            result = "No 3d sound";
            break;
          case -2146107016:
            result = "Already buffered";
            break;
          case -2146107015:
            result = "Not buffered";
            break;
          case -2146107014:
            return "Hosting";
          case -2146107013:
            result = "Not hosting";
            break;
          case -2146107012:
            return "Invalid device";
          case -2146107011:
            result = "Record system error";
            break;
          case -2146107010:
            result = "Playback system error";
            break;
          case -2146107009:
            result = "Send error";
            break;
          default:
            return "n/a";
        }
        return result;
      }
    }
    return "User cancel";
  }
  if ( a1 == -2146107092 )
    return "Session lost";
  if ( a1 > -2147220890 )
  {
    if ( a1 <= -2147220476 )
    {
      if ( a1 == -2147220476 )
        return "Seeking not supported for this object.";
      if ( a1 > -2147220855 )
      {
        if ( a1 > -2147220736 )
        {
          if ( a1 > -2147220494 )
          {
            switch ( a1 )
            {
              case -2147220481:
                return "Device installer errors.";
              case -2147220480:
                return "Registry entry or DLL for class installer invalid or class installer not found.";
              case -2147220479:
                return "The user cancelled the install operation. & The stream already has allocated samples and the surf"
                       "ace doesn't match the sample format.";
              case -2147220478:
                return "The INF file for the selected device could not be found or is invalid or is damaged. & The specif"
                       "ied purpose ID can't be used for the call.";
              case -2147220477:
                return "No stream can be found with the specified attributes.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2147220494:
                return "A registry entry is corrupt.";
              case -2147220735:
                return "DIERR_DRIVERFIRST+1";
              case -2147220734:
                return "DIERR_DRIVERFIRST+2";
              case -2147220733:
                return "DIERR_DRIVERFIRST+3";
              case -2147220732:
                return "DIERR_DRIVERFIRST+4";
              case -2147220731:
                return "DIERR_DRIVERFIRST+5";
            }
          }
          return "n/a";
        }
        if ( a1 == -2147220736 )
        {
          return "Device driver-specific codes. Unless the specific driver has been precisely identified, no meaning shou"
                 "ld be attributed to these values other than that the driver originated the error.";
        }
        else
        {
          switch ( a1 )
          {
            case -2147220854:
              result = "The current parental level was too low.";
              break;
            case -2147220853:
              result = "The current audio is not karaoke content.";
              break;
            case -2147220850:
              result = "Frame step is not supported on this configuration.";
              break;
            case -2147220849:
              result = "The specified stream is disabled and cannot be selected.";
              break;
            case -2147220848:
              result = "The operation depends on the current title number, however the navigator has not yet entered the "
                       "VTSM or the title domains, so the 'current' title index is unknown.";
              break;
            case -2147220847:
              result = "The specified path does not point to a valid DVD disc.";
              break;
            case -2147220846:
              result = "There is currently no resume information.";
              break;
            case -2147220845:
              result = "This thread has already blocked this output pin.  There is no need to call IPinFlowControl::Block() again.";
              break;
            case -2147220844:
              result = "IPinFlowControl::Block() has been called on another thread.  The current thread cannot make any a"
                       "ssumptions about this pin's block state.";
              break;
            case -2147220843:
              result = "An operation failed due to a certification failure.";
              break;
            default:
              return "n/a";
          }
        }
      }
      else if ( a1 == -2147220855 )
      {
        return "Currently there is no GoUp (Annex J user function) program chain (PGC).";
      }
      else
      {
        switch ( a1 )
        {
          case -2147220887:
            result = "The Video CD can't be read correctly by the device or is the data is corrupt.";
            break;
          case -2147220879:
            result = "There is not enough Video Memory at this display resolution and number of colors. Reducing resolution might help.";
            break;
          case -2147220878:
            result = "The VideoPort connection negotiation process has failed.";
            break;
          case -2147220877:
            result = "Either DirectDraw has not been installed or the Video Card capabilities are not suitable. Make sure"
                     " the display is not in 16 color mode.";
            break;
          case -2147220876:
            result = "No VideoPort hardware is available, or the hardware is not responding.";
            break;
          case -2147220875:
            result = "No Capture hardware is available, or the hardware is not responding.";
            break;
          case -2147220874:
            result = "This User Operation is inhibited by DVD Content at this time.";
            break;
          case -2147220873:
            result = "This Operation is not permitted in the current domain.";
            break;
          case -2147220872:
            result = "The specified button is invalid or is not present at the current time, or there is no button presen"
                     "t at the specified location.";
            break;
          case -2147220871:
            result = "DVD-Video playback graph has not been built yet.";
            break;
          case -2147220870:
            result = "DVD-Video playback graph building failed.";
            break;
          case -2147220869:
            result = "DVD-Video playback graph could not be built due to insufficient decoders.";
            break;
          case -2147220868:
            result = "Version number of DirectDraw not suitable. Make sure to install dx5 or higher version.";
            break;
          case -2147220867:
            result = "Copy protection cannot be enabled. Please make sure any other copy protected content is not being shown now.";
            break;
          case -2147220865:
            result = "This object cannot be used anymore as its time has expired.";
            break;
          case -2147220863:
            result = "The operation cannot be performed at the current playback speed.";
            break;
          case -2147220862:
            result = "The specified menu doesn't exist.";
            break;
          case -2147220861:
            result = "The specified command was either cancelled or no longer exists.";
            break;
          case -2147220860:
            result = "The data did not contain a recognized version.";
            break;
          case -2147220859:
            result = "The state data was corrupt.";
            break;
          case -2147220858:
            result = "The state data is from a different disc.";
            break;
          case -2147220857:
            result = "The region was not compatible with the current drive.";
            break;
          case -2147220856:
            result = "The requested DVD stream attribute does not exist.";
            break;
          default:
            return "n/a";
        }
      }
      return result;
    }
    if ( a1 <= -2147024887 )
    {
      if ( a1 == -2147024887 )
        return "The storage control block address is invalid.";
      if ( a1 <= -2147219194 )
      {
        if ( a1 == -2147219194 )
          return "An error occurred when attempting to reset a device.";
        if ( a1 > -2147220470 )
        {
          switch ( a1 )
          {
            case -2147219199:
              return "Could not initialize Direct3D.";
            case -2147219198:
              return "No device could be found with the specified device settings.";
            case -2147219197:
              return "A media file could not be found.";
            case -2147219196:
              return "The device interface has a non-zero reference count, meaning that some objects were not released.";
            case -2147219195:
              return "An error occurred when attempting to create a device.";
          }
          return "n/a";
        }
        switch ( a1 )
        {
          case -2147220470:
            return "The object is not in running state.";
          case -2147220475:
            return "The stream formats are not compatible.";
          case -2147220474:
            return "The sample is busy.";
          case -2147220473:
            return "The object can't accept the call because its initialize function or equivalent has not been called.";
          case -2147220472:
            return "MS_E_SOURCEALREADYDEFINED";
        }
        return "The stream type is not valid for this operation.";
      }
      if ( a1 <= -2147024893 )
      {
        switch ( a1 )
        {
          case -2147024893:
            return "The system cannot find the path specified.";
          case -2147219193:
            return "An error occurred in the device create callback function.";
          case -2147219192:
            return "An error occurred in the device reset callback function.";
          case -2147219191:
            return "Incorrect version of Direct3D or D3DX.";
          case -2147219190:
            return "The device was removed.";
          case -2147024894:
            return "The system cannot find the file specified.";
        }
        return "n/a";
      }
      if ( a1 == -2147024892 )
        return "The system cannot open the file.";
      if ( a1 == -2147024891 )
        return "Access is denied";
      if ( a1 != -2147024890 )
      {
        if ( a1 == -2147024888 )
          return "Not enough storage is available to process this command.";
        return "n/a";
      }
      return "Invalid handle";
    }
    if ( a1 <= -2147023743 )
    {
      if ( a1 == -2147023743 )
        return "The application was written for an unsupported prerelease version of DirectInput.";
      if ( a1 > -2147024866 )
      {
        switch ( a1 )
        {
          case -2147024809:
            return "An invalid parameter was passed to the returning function";
          case -2147024777:
            return "The object could not be created due to an incompatible driver version or mismatched or incomplete driver components.";
          case -2147024726:
            return "The operation cannot be performed while the device is acquired.";
          case -2147024637:
            return "No more items.";
          case -2147023746:
            return "The application requires a newer version of DirectInput.";
        }
        return "n/a";
      }
      switch ( a1 )
      {
        case -2147024866:
          return "Access to the device has been lost.  It must be re-acquired.";
        case -2147024886:
          return "The environment is incorrect.";
        case -2147024885:
          return "An attempt was made to load a program with an incorrect format.";
        case -2147024884:
          return "The operation cannot be performed unless the device is acquired.";
        case -2147024882:
          return "Ran out of memory";
      }
      if ( a1 != -2147024875 )
        return "n/a";
      return "This object has not been initialized";
    }
    if ( a1 <= -2146107272 )
    {
      if ( a1 != -2146107272 )
      {
        if ( a1 == -2147023728 )
          return "The specified property ID is not supported for the specified property set.";
        if ( a1 == -2147023726 )
          return "The specified property set is not supported.";
        if ( a1 != -2147023649 )
        {
          if ( a1 != -2146107362 )
          {
            if ( a1 == -2146107318 )
              return "Exception";
            return "n/a";
          }
          return "Buffer too small";
        }
        return "This object is already initialized";
      }
      return "Invalid flags";
    }
    if ( a1 != -2146107262 )
    {
      if ( a1 != -2146107257 )
      {
        if ( a1 != -2146107247 )
        {
          if ( a1 == -2146107242 )
            return "Invalid handle";
          return "n/a";
        }
        return "Invalid group";
      }
      return "Invalid player";
    }
    return "Invalid object";
  }
  if ( a1 == -2147220890 )
    return "Pins cannot connect due to not supporting the same transport.";
  if ( a1 > -2147220957 )
  {
    switch ( a1 )
    {
      case -2147220956:
        result = "The operation could not be performed because the filter is not stopped.";
        break;
      case -2147220955:
        result = "The operation could not be performed because the filter is not paused.";
        break;
      case -2147220954:
        result = "The operation could not be performed because the filter is not running.";
        break;
      case -2147220953:
        result = "The operation could not be performed because the filter is in the wrong state.";
        break;
      case -2147220952:
        result = "The sample start time is after the sample end time.";
        break;
      case -2147220951:
        result = "The supplied rectangle is invalid.";
        break;
      case -2147220950:
        result = "This pin cannot use the supplied media type.";
        break;
      case -2147220949:
        result = "This sample cannot be rendered.";
        break;
      case -2147220948:
        result = "This sample cannot be rendered because the end of the stream has been reached.";
        break;
      case -2147220947:
        result = "An attempt to add a filter with a duplicate name failed.";
        break;
      case -2147220946:
        result = "A time-out has expired.";
        break;
      case -2147220945:
        result = "The file format is invalid.";
        break;
      case -2147220944:
        result = "The list has already been exhausted.";
        break;
      case -2147220943:
        result = "The filter graph is circular.";
        break;
      case -2147220942:
        result = "Updates are not allowed in this state.";
        break;
      case -2147220941:
        result = "An attempt was made to queue a command for a time in the past.";
        break;
      case -2147220940:
        result = "The queued command has already been canceled.";
        break;
      case -2147220939:
        result = "Cannot render the file because it is corrupt.";
        break;
      case -2147220938:
        result = "An overlay advise link already exists.";
        break;
      case -2147220936:
        result = "No full-screen modes are available.";
        break;
      case -2147220935:
        result = "This Advise cannot be canceled because it was not successfully set.";
        break;
      case -2147220934:
        result = "A full-screen mode is not available.";
        break;
      case -2147220933:
        result = "Cannot call IVideoWindow methods while in full-screen mode.";
        break;
      case -2147220928:
        result = "The media type of this file is not recognized.";
        break;
      case -2147220927:
        result = "The source filter for this file could not be loaded.";
        break;
      case -2147220925:
        result = "A file appeared to be incomplete.";
        break;
      case -2147220924:
        result = "The version number of the file is invalid.";
        break;
      case -2147220921:
        result = "This file is corrupt: it contains an invalid class identifier.";
        break;
      case -2147220920:
        result = "This file is corrupt: it contains an invalid media type.";
        break;
      case -2147220919:
        result = "No time stamp has been set for this sample.";
        break;
      case -2147220911:
        result = "No media time stamp has been set for this sample.";
        break;
      case -2147220910:
        result = "No media time format has been selected.";
        break;
      case -2147220909:
        result = "Cannot change balance because audio device is mono only.";
        break;
      case -2147220907:
        return "Cannot play back the video stream: no suitable decompressor could be found.";
      case -2147220906:
        result = "Cannot play back the audio stream: no audio hardware is available, or the hardware is not responding.";
        break;
      case -2147220903:
        return "Cannot play back the video stream: format 'RPZA' is not supported.";
      case -2147220901:
        result = "ActiveMovie cannot play MPEG movies on this processor.";
        break;
      case -2147220900:
        result = "Cannot play back the audio stream: the audio format is not supported.";
        break;
      case -2147220899:
        result = "Cannot play back the video stream: the video format is not supported.";
        break;
      case -2147220898:
        result = "ActiveMovie cannot play this video stream because it falls outside the constrained standard.";
        break;
      case -2147220897:
        result = "Cannot perform the requested function on an object that is not in the filter graph.";
        break;
      case -2147220895:
        result = "Cannot get or set time related information on an object that is using a time format of TIME_FORMAT_NONE.";
        break;
      case -2147220894:
        result = "The connection cannot be made because the stream is read only and the filter alters the data.";
        break;
      case -2147220892:
        result = "The buffer is not full enough.";
        break;
      case -2147220891:
        result = "Cannot play back the file.  The format is not supported.";
        break;
      default:
        return "n/a";
    }
  }
  else
  {
    if ( a1 == -2147220957 )
      return "The state changed while waiting to process the sample.";
    if ( a1 > -2147220980 )
    {
      switch ( a1 )
      {
        case -2147220979:
          result = "The buffer is not big enough.";
          break;
        case -2147220978:
          result = "An invalid alignment was specified.";
          break;
        case -2147220977:
          result = "Cannot change allocated memory while the filter is active.";
          break;
        case -2147220976:
          result = "One or more buffers are still active.";
          break;
        case -2147220975:
          result = "Cannot allocate a sample when the allocator is not active.";
          break;
        case -2147220974:
          result = "Cannot allocate memory because no size has been set.";
          break;
        case -2147220973:
          result = "Cannot lock for synchronization because no clock has been defined.";
          break;
        case -2147220972:
          result = "Quality messages could not be sent because no quality sink has been defined.";
          break;
        case -2147220971:
          result = "A required interface has not been implemented.";
          break;
        case -2147220970:
          result = "An object or name was not found.";
          break;
        case -2147220969:
          result = "No combination of intermediate filters could be found to make the connection.";
          break;
        case -2147220968:
          result = "No combination of filters could be found to render the stream.";
          break;
        case -2147220967:
          result = "Could not change formats dynamically.";
          break;
        case -2147220966:
          result = "No color key has been set.";
          break;
        case -2147220965:
          result = "Current pin connection is not using the IOverlay transport.";
          break;
        case -2147220964:
          result = "Current pin connection is not using the IMemInputPin transport.";
          break;
        case -2147220963:
          result = "Setting a color key would conflict with the palette already set.";
          break;
        case -2147220962:
          result = "Setting a palette would conflict with the color key already set.";
          break;
        case -2147220961:
          result = "No matching color key is available.";
          break;
        case -2147220960:
          result = "No palette is available.";
          break;
        case -2147220959:
          result = "Display does not use a palette.";
          break;
        case -2147220958:
          result = "Too many colors for the current display settings.";
          break;
        default:
          return "n/a";
      }
    }
    else
    {
      if ( a1 == -2147220980 )
        return "No buffer space has been set";
      if ( a1 <= -2147220992 )
      {
        if ( a1 == -2147220992 )
          return "Unable to IDirectInputJoyConfig_Acquire because the user does not have sufficient privileges to change "
                 "the joystick configuration. & An invalid media type was specified";
        if ( a1 > -2147467259 )
        {
          switch ( a1 )
          {
            case -2147418113:
              return "Catastrophic failure";
            case -2147221232:
              return "This object does not support aggregation";
            case -2147221164:
              return "Class not registered";
            case -2147221008:
              return "CoInitialize has not been called.";
            case -2147221007:
              return "CoInitialize has already been called.";
          }
        }
        else
        {
          switch ( a1 )
          {
            case -2147467259:
              return "An undetermined error occurred";
            case -2147483638:
              return "The data necessary to complete this operation is not yet available.";
            case -2147467263:
              return "The function called is not supported at this time";
            case -2147467262:
              return "The requested COM interface is not available";
            case -2147467261:
              return "Invalid pointer";
            case -2147467260:
              return "Operation aborted";
          }
        }
        return "n/a";
      }
      switch ( a1 )
      {
        case -2147220991:
          result = "The device is full. & An invalid media subtype was specified.";
          break;
        case -2147220990:
          result = "Not all the requested information fit into the buffer. & This object can only be created as an aggregated object.";
          break;
        case -2147220989:
          result = "The effect is not downloaded. & The enumerator has become invalid.";
          break;
        case -2147220988:
          result = "The device cannot be reinitialized because there are still effects attached to it. & At least one of "
                   "the pins involved in the operation is already connected.";
          break;
        case -2147220987:
          result = "The operation cannot be performed unless the device is acquired in DISCL_EXCLUSIVE mode. & This opera"
                   "tion cannot be performed because the filter is active.";
          break;
        case -2147220986:
          result = "The effect could not be downloaded because essential information is missing.  For example, no axes ha"
                   "ve been associated with the effect, or no type-specific information has been created. & One of the sp"
                   "ecified pins supports no media types.";
          break;
        case -2147220985:
          result = "Attempted to read buffered device data from a device that is not buffered. & There is no common media"
                   " type between these pins.";
          break;
        case -2147220984:
          result = "An attempt was made to modify parameters of an effect while it is playing.  Not all hardware devices "
                   "support altering the parameters of an effect while it is playing. & Two pins of the same direction ca"
                   "nnot be connected together.";
          break;
        case -2147220983:
          result = "The operation could not be completed because the device is not plugged in. & The operation cannot be "
                   "performed because the pins are not connected.";
          break;
        case -2147220982:
          result = "SendDeviceData failed because more information was requested to be sent than can be sent to the devic"
                   "e.  Some devices have restrictions on how much data can be sent to them.  (For example, there might b"
                   "e a limit on the number of buttons that can be pressed at once.) & No sample buffer allocator is available.";
          break;
        case -2147220981:
          result = "A mapper file function failed because reading or writing the user or IHV settings file failed. & A ru"
                   "n-time error occurred.";
          break;
        default:
          return "n/a";
      }
    }
  }
  return result;
}

  /**
   * Address: 0x00B542F1 (FUN_00B542F1)
   *
   * HRESULT
   *
   * What it does:
   * Maps DirectX/COM HRESULT values to the engine's static diagnostic text
   * table as wide-character literals, returning L"n/a" when no mapping exists.
   */
const wchar_t* __stdcall D3DErrorToWideString(const long a1)
{
  const wchar_t *result; // eax

  if ( a1 > -2005532092 )
  {
    if ( a1 <= -2005532042 )
    {
      if ( a1 == -2005532042 )
        return L"An attempt was made to allocate non-local video memory from a device that does not support non-local video memory.";
      switch ( a1 )
      {
        case -2005532091:
          result = L"An attempt was made to set the cooperative level when it was already set to exclusive.";
          break;
        case -2005532090:
          result = L"An attempt has been made to flip a surface that is not flippable.";
          break;
        case -2005532089:
          result = L"Can't duplicate primary & 3D surfaces, or surfaces that are implicitly created.";
          break;
        case -2005532088:
          result = L"Surface was not locked.  An attempt to unlock a surface that was not locked at all, or by this proces"
                   L"s, has been attempted.";
          break;
        case -2005532087:
          result = L"Windows can not create any more DCs, or a DC was requested for a paltte-indexed surface when the surf"
                   L"ace had no palette AND the display mode was not palette-indexed (in this case DirectDraw cannot selec"
                   L"t a proper palette into the DC)";
          break;
        case -2005532086:
          result = L"No DC was ever created for this surface.";
          break;
        case -2005532085:
          result = L"This surface can not be restored because it was created in a different mode.";
          break;
        case -2005532084:
          result = L"This surface can not be restored because it is an implicitly created surface.";
          break;
        case -2005532083:
          result = L"The surface being used is not a palette-based surface";
          break;
        case -2005532082:
          result = L"The display is currently in an unsupported mode";
          break;
        case -2005532081:
          result = L"Operation could not be carried out because there is no mip-map texture mapping hardware present or available.";
          break;
        case -2005532080:
          result = L"The requested action could not be performed because the surface was of the wrong type.";
          break;
        case -2005532072:
          result = L"Device does not support optimized surfaces, therefore no video memory optimized surfaces";
          break;
        case -2005532071:
          result = L"Surface is an optimized surface, but has not yet been allocated any memory";
          break;
        case -2005532070:
          result = L"Attempt was made to create or set a device window without first setting the focus window";
          break;
        case -2005532069:
          result = L"Attempt was made to set a palette on a mipmap sublevel";
          break;
        case -2005532052:
          result = L"A DC has already been returned for this surface. Only one DC can be retrieved per surface.";
          break;
        default:
          return L"n/a";
      }
      return result;
    }
    if ( a1 > -2005396959 )
    {
      if ( a1 <= -2005336063 )
      {
        if ( a1 == -2005336063 )
          return L"There are too many unique state objects.";
        switch ( a1 )
        {
          case -2005396958:
            result = L"The file contains an invalid parameter control track.";
            break;
          case -2005396957:
            result = L"A script written in AudioVBScript could not be read because it contained a statement that is not al"
                     L"lowed by the AudioVBScript language.";
            break;
          case -2005396956:
            result = L"A script routine written in AudioVBScript failed because an invalid operation occurred.  For exampl"
                     L"e, adding the number 3 to a segment object would produce this error.  So would attempting to call a"
                     L" routine that doesn't exist.";
            break;
          case -2005396955:
            result = L"A script routine written in AudioVBScript failed because a function outside of a script failed to c"
                     L"omplete. For example, a call to PlaySegment that fails to play because of low memory would return this error.";
            break;
          case -2005396954:
            result = L"The Performance has set up some PChannels using the AssignPChannel command, which makes it not capa"
                     L"ble of supporting audio paths.";
            break;
          case -2005396953:
            result = L"This is the inverse of the previous error. The Performance has set up some audio paths, which makes"
                     L" is incompatible with the calls to allocate pchannels, etc. ";
            break;
          case -2005396952:
            result = L"A segment or song was asked for its embedded audio path configuration, but there isn't any. ";
            break;
          case -2005396951:
            result = L"An audiopath is inactive, perhaps because closedown was called.";
            break;
          case -2005396950:
            result = L"An audiopath failed to create because a requested buffer could not be created.";
            break;
          case -2005396949:
            result = L"An audiopath could not be used for playback because it lacked port assignments.";
            break;
          case -2005396948:
            result = L"Attempt was made to play segment in audiopath mode and there was no audiopath.";
            break;
          case -2005396947:
            result = L"Invalid data was found in a RIFF file chunk.";
            break;
          case -2005396946:
            result = L"Attempt was made to create an audiopath that sends to a global effects buffer which did not exist.";
            break;
          case -2005396945:
            result = L"The file does not contain a valid container object.";
            break;
          default:
            return L"n/a";
        }
        return result;
      }
      if ( a1 <= -931722305 )
      {
        if ( a1 == -931722305 )
          return L"Z buffer has not been created";
        if ( a1 > -1966669805 )
        {
          if ( a1 > -1072898029 )
          {
            if ( a1 > -1072898010 )
            {
              if ( a1 <= -931722310 )
              {
                switch ( a1 )
                {
                  case -931722310:
                    return L"The Device Index passed in is invalid";
                  case -1072897501:
                    return L"The validate method failed because the document does not contain exactly one root node.";
                  case -1072897500:
                    return L"The validate method failed because a DTD or schema was not specified in the document.";
                  case -931722312:
                    return L"Out of memory";
                  case -931722311:
                    return L"A NULL pointer was passed as a parameter";
                }
                return L"n/a";
              }
              switch ( a1 )
              {
                case -931722309:
                  return L"DirectDraw has not been created";
                case -931722308:
                  return L"Direct3D has not been created";
                case -931722307:
                  return L"Direct3D device has not been created";
                default:
                  return L"Primary surface has not been created";
              }
            }
            else if ( a1 == -1072898010 )
            {
              return L"Expecting: %1.";
            }
            else
            {
              switch ( a1 )
              {
                case -1072898028:
                  result = L"Element content is invalid according to the DTD or schema.";
                  break;
                case -1072898027:
                  result = L"The attribute '%1' on this element is not defined in the DTD or schema.";
                  break;
                case -1072898026:
                  result = L"Attribute '%1' has a value that does not match the fixed value defined in the DTD or schema.";
                  break;
                case -1072898025:
                  result = L"Attribute '%1' has an invalid value according to the DTD or schema.";
                  break;
                case -1072898024:
                  result = L"Text is not allowed in this element according to the DTD or schema.";
                  break;
                case -1072898023:
                  result = L"An attribute declaration cannot contain multiple fixed values: '%1'.";
                  break;
                case -1072898020:
                  result = L"Reference to undeclared element: '%1'.";
                  break;
                case -1072898018:
                  result = L"Attribute '%1' must be a #FIXED attribute.";
                  break;
                case -1072898016:
                  result = L"Required attribute '%1' is missing.";
                  break;
                default:
                  return L"n/a";
              }
            }
          }
          else
          {
            if ( a1 == -1072898029 )
              return L"The name of the top-most element must match the name of the DOCTYPE declaration.";
            if ( a1 <= -1072898046 )
            {
              if ( a1 == -1072898046 )
                return L"Reference to undefined entity '%1'.";
              if ( a1 > -1966669566 )
              {
                switch ( a1 )
                {
                  case -1966669565:
                    return L"Missing an RPC curve.";
                  case -1966669564:
                    return L"Missing data for an audition command.";
                  case -1966669563:
                    return L"Unknown command.";
                  case -1966669562:
                    return L"Missing a DSP parameter.";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -1966669566:
                    return L"Missing a soundbank.";
                  case -1966669804:
                    return L"Unable to select a variation.";
                  case -1966669803:
                    return L"There can be only one audition engine.";
                  case -1966669802:
                    return L"The wavebank is not prepared.";
                  case -1966669567:
                    return L"Error writing a file during auditioning.";
                }
              }
              return L"n/a";
            }
            switch ( a1 )
            {
              case -1072898045:
                result = L"Entity '%1' contains an infinite entity reference loop.";
                break;
              case -1072898044:
                result = L"Cannot use the NDATA keyword in a parameter entity declaration.";
                break;
              case -1072898043:
                result = L"Cannot use a general parsed entity '%1' as the value for attribute '%2'.";
                break;
              case -1072898042:
                result = L"Cannot use unparsed entity '%1' in an entity reference.";
                break;
              case -1072898041:
                result = L"Cannot reference an external general parsed entity '%1' in an attribute value.";
                break;
              case -1072898035:
                result = L"The element '%1' is used but not declared in the DTD or schema.";
                break;
              case -1072898034:
                result = L"The attribute '%1' references the ID '%2', which is not defined in the document.";
                break;
              case -1072898031:
                result = L"Element cannot be empty according to the DTD or schema.";
                break;
              case -1072898030:
                result = L"Element content is incomplete according to the DTD or schema.";
                break;
              default:
                return L"n/a";
            }
          }
        }
        else
        {
          if ( a1 == -1966669805 )
            return L"No wavebank exists for desired operation.";
          if ( a1 > -2003435509 )
          {
            if ( a1 > -1966669815 )
            {
              switch ( a1 )
              {
                case -1966669814:
                  result = L"Invalid variable index.";
                  break;
                case -1966669813:
                  result = L"Invalid category.";
                  break;
                case -1966669812:
                  result = L"Invalid cue index.";
                  break;
                case -1966669811:
                  result = L"Invalid wave index.";
                  break;
                case -1966669810:
                  result = L"Invalid track index.";
                  break;
                case -1966669809:
                  result = L"Invalid sound offset or index.";
                  break;
                case -1966669808:
                  result = L"Error reading a file.";
                  break;
                case -1966669807:
                  result = L"Unknown event type.";
                  break;
                case -1966669806:
                  result = L"Invalid call of method of function from callback.";
                  break;
                default:
                  return L"n/a";
              }
            }
            else
            {
              if ( a1 == -1966669815 )
                return L"Global Settings not loaded.";
              if ( a1 <= -1966669820 )
              {
                switch ( a1 )
                {
                  case -1966669820:
                    return L"No notification callback.";
                  case -2003435508:
                    return L"An audio device became unusable (unplugged, etc).";
                  case -1966669823:
                    return L"The engine is already initialized.";
                  case -1966669822:
                    return L"The engine has not been initialized.";
                  case -1966669821:
                    return L"The engine has expired (demo or pre-release version).";
                }
                return L"n/a";
              }
              switch ( a1 )
              {
                case -1966669819:
                  return L"Notification already registered.";
                case -1966669818:
                  return L"Invalid usage.";
                case -1966669817:
                  return L"Invalid data.";
                default:
                  return L"Fail to play due to instance limit.";
              }
            }
          }
          else
          {
            if ( a1 == -2003435509 )
              return L"Failed to instantiate an effect.";
            if ( a1 <= -2003435519 )
            {
              if ( a1 == -2003435519 )
                return L"Method cannot be called before IXAudio2::Initialize.";
              if ( a1 > -2005270522 )
              {
                switch ( a1 )
                {
                  case -2005270521:
                    return L"Device reset.";
                  case -2005270518:
                    return L"Was still drawing.";
                  case -2005270496:
                    return L"An internal driver error occurred.";
                  case -2005270495:
                    return L"The application attempted to perform an operation on an DXGI output that is only legal after "
                           L"the output has been claimed for exclusive owenership.";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -2005270522:
                    return L"Device hung.";
                  case -2005270527:
                    return L"The application has made an erroneous API call that it had enough information to avoid. This "
                           L"error is intended to denote that the application should be altered to avoid the error. Use of"
                           L" the debug version of the DXGI.DLL will provide run-time debug output with further information.";
                  case -2005270526:
                    return L"The item requested was not found. For GetPrivateData calls, this means that the specified GUI"
                           L"D had not been previously associated with the object.";
                  case -2005270525:
                    return L"The specified size of the destination buffer is too small to hold the requested data.";
                  case -2005270524:
                    return L"Unsupported.";
                  case -2005270523:
                    return L"Device removed.";
                }
              }
              return L"n/a";
            }
            switch ( a1 )
            {
              case -2003435518:
                result = L"IXAudio2::Initialize was called redundantly.";
                break;
              case -2003435517:
                result = L"One of the given arguments was invalid.";
                break;
              case -2003435516:
                result = L"One of the flags was invalid for this method.";
                break;
              case -2003435515:
                result = L"A required pointer argument was NULL.";
                break;
              case -2003435514:
                result = L"An given index was out of the valid range.";
                break;
              case -2003435513:
                result = L"The method call is currently invalid.";
                break;
              case -2003435512:
                result = L"Object cannot be destroyed because it is still in use.";
                break;
              case -2003435511:
                result = L"Requested operation is unsupported on this platform/device.";
                break;
              case -2003435510:
                result = L"The XMA hardware suffered an unrecoverable error.";
                break;
              default:
                return L"n/a";
            }
          }
        }
        return result;
      }
      if ( a1 <= 0 )
      {
        if ( !a1 )
          return L"The function completed successfully";
        switch ( a1 )
        {
          case -931722304:
            result = L"Backbuffer has not been created";
            break;
          case -931722303:
            result = L"Failed to update caps database after changing display mode";
            break;
          case -931722302:
            result = L"Could not create Z buffer";
            break;
          case -931722301:
            result = L"Display mode is not valid";
            break;
          case -931722300:
            result = L"One or more of the parameters passed is invalid";
            break;
          case -931722299:
            result = L"D3DX failed to initialize itself";
            break;
          case -931722298:
            result = L"D3DX failed to start up";
            break;
          case -931722297:
            result = L"D3DXInitialize() must be called first";
            break;
          case -931722296:
            result = L"D3DX is not initialized yet";
            break;
          case -931722295:
            result = L"Failed to render text to the surface";
            break;
          case -931722294:
            result = L"Bad D3DX context";
            break;
          case -931722293:
            result = L"The requested device capabilities are not supported";
            break;
          case -931722292:
            result = L"The image file format is unrecognized";
            break;
          case -931722291:
            result = L"The image file loading library error";
            break;
          case -931722290:
            result = L"Could not obtain device caps";
            break;
          case -931722289:
            result = L"Resize does not work for full-screen";
            break;
          case -931722288:
            result = L"Resize does not work for non-windowed contexts";
            break;
          case -931722287:
            result = L"Front buffer already exists";
            break;
          case -931722286:
            result = L"The app is using the primary in full-screen mode";
            break;
          case -931722285:
            result = L"Could not get device context";
            break;
          case -931722284:
            result = L"Could not bitBlt";
            break;
          case -931722283:
            result = L"There is no surface backing up this texture";
            break;
          case -931722282:
            result = L"There is no such miplevel for this surface";
            break;
          case -931722281:
            result = L"The surface is not paletted";
            break;
          case -931722280:
            result = L"An error occured while enumerating surface formats";
            break;
          case -931722279:
            result = L"D3DX only supports color depths of 16 bit or greater";
            break;
          case -931722278:
            result = L"The file format is invalid";
            break;
          case -931722277:
            result = L"No suitable match found";
            break;
          default:
            return L"n/a";
        }
        return result;
      }
      if ( a1 <= 262147 )
      {
        if ( a1 == 262147 )
          return L"End of stream. Sample not updated.";
        switch ( a1 )
        {
          case 1:
            result = L"Call successful, but returned FALSE";
            break;
          case 2:
            return L"The system cannot find the file specified.";
          case 3:
            return L"The system cannot find the path specified.";
          case 4:
            return L"The system cannot open the file.";
          case 5:
            result = L"Access is denied.";
            break;
          case 6:
            result = L"The handle is invalid.";
            break;
          case 8:
            return L"Not enough storage is available to process this command.";
          case 9:
            return L"The storage control block address is invalid.";
          case 10:
            return L"The environment is incorrect.";
          case 11:
            return L"An attempt was made to load a program with an incorrect format.";
          case 14:
            result = L"The system cannot find the drive specified.";
            break;
          default:
            return L"n/a";
        }
        return result;
      }
      if ( a1 <= 262797 )
      {
        if ( a1 == 262797 )
          return L"The seek into the movie was not frame accurate.";
        if ( a1 > 262744 )
        {
          if ( a1 > 262760 )
          {
            switch ( a1 )
            {
              case 262768:
                return L"The stop time for the sample was not set.";
              case 262782:
                return L"There was no preview pin available, so the capture pin output is being split to provide both capt"
                       L"ure and preview.";
              case 262784:
                return L"The current title was not a sequential set of chapters (PGC), and the returned timing information"
                       L" might not be continuous.";
              case 262796:
                return L"The audio stream did not contain sufficient information to determine the contents of each channel.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case 262760:
                return L"The graph can't be cued because of lack of or corrupt data.";
              case 262746:
                return L"Cannot play back the video stream: format 'RPZA' is not supported.";
              case 262752:
                return L"The value returned had to be estimated.  It's accuracy can not be guaranteed.";
              case 262755:
                return L"This success code is reserved for internal purposes within ActiveMovie.";
              case 262759:
                return L"The stream has been turned off.";
            }
          }
        }
        else
        {
          if ( a1 == 262744 )
            return L"Cannot play back the audio stream: no audio hardware is available.";
          if ( a1 > 262725 )
          {
            switch ( a1 )
            {
              case 262726:
                return L"Some connections have failed and have been deferred.";
              case 262736:
                return L"The resource specified is no longer needed.";
              case 262740:
                return L"A connection could not be made with the media type in the persistent graph, but has been made wit"
                       L"h a negotiated media type.";
              case 262743:
                return L"Cannot play back the video stream: no suitable decompressor could be found.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case 262725:
                return L"The file contained some property settings that were not used.";
              case 262403:
                return L"The end of the list has been reached.";
              case 262701:
                return L"An attempt to add a filter with a duplicate name succeeded with a modified name.";
              case 262711:
                return L"The state transition has not completed.";
              case 262722:
                return L"Some of the streams in this movie are in an unsupported format.";
            }
          }
        }
        return L"n/a";
      }
      if ( a1 <= 142086658 )
      {
        if ( a1 == 142086658 )
          return L"Return value from IDirectMusicTrack::Play() which indicates to the segment that the track has no more d"
                 L"ata after mtEnd.";
        if ( a1 > 142082058 )
        {
          switch ( a1 )
          {
            case 142086289:
              return L"The object could only load partially. This can happen if some components are not registered properl"
                     L"y, such as embedded tracks and tools. This can also happen if some content is missing. For example,"
                     L" if a segment uses a DLS collection that is not in the loader's current search directory.";
            case 142086290:
              return L"Return value from IDirectMusicBand::Download() which indicates that some of the instruments safely "
                     L"downloaded, but others failed. This usually occurs when some instruments are on PChannels not suppo"
                     L"rted by the performance or port.";
            case 142086656:
              return L"Return value from IDirectMusicTool::ProcessPMsg() which indicates to the performance that it should"
                     L" cue the PMsg again automatically.";
            case 142086657:
              return L"Return value from IDirectMusicTool::ProcessPMsg() which indicates to the performance that it should"
                     L" free the PMsg automatically.";
          }
        }
        else
        {
          switch ( a1 )
          {
            case 142082058:
              return L"The call succeeded, but we had to substitute the 3D algorithm";
            case 1376261:
              return L"Full duplex";
            case 1376266:
              return L"Half duplex";
            case 1376272:
              return L"Pending";
            case 141953135:
              return L"The call succeeded but there won't be any mipmaps generated";
          }
        }
        return L"n/a";
      }
      if ( a1 <= 142086676 )
      {
        switch ( a1 )
        {
          case 142086676:
            return L"Returned from IDirectMusicPerformance::MIDIToMusic(),  and IDirectMusicPerformance::MusicToMIDI(), th"
                   L"is indicates  that the note conversion generated a note value that is above 127, so it has been bumpe"
                   L"d down one or more octaves to be in the proper MIDI range of 0 through 127.  Note that this is valid "
                   L"for MIDIToMusic() when using play modes DMUS_PLAYMODE_FIXEDTOCHORD and DMUS_PLAYMODE_FIXEDTOKEY, both"
                   L" of which store MIDI values in wMusicValue. With MusicToMIDI(), it is valid for all play modes. Ofcou"
                   L"rse, DMUS_PLAYMODE_FIXED will never return this success code.";
          case 142086672:
            return L"Returned string has been truncated to fit the buffer size.";
          case 142086673:
            return L"Returned from IDirectMusicGraph::StampPMsg(), this indicates that the PMsg is already stamped with th"
                   L"e last tool in the graph. The returned PMsg's tool pointer is now NULL.";
          case 142086674:
            return L"Returned from IDirectMusicPerformance::MusicToMIDI(), this indicates  that no note has been calculate"
                   L"d because the music value has the note  at a position higher than the top note of the chord. This app"
                   L"lies only to DMUS_PLAYMODE_NORMALCHORD play mode. This success code indicates that the caller should "
                   L"not do anything with the note. It is not meant to be played against this chord.";
          case 142086675:
            return L"Returned from IDirectMusicPerformance::MIDIToMusic(),  and IDirectMusicPerformance::MusicToMIDI(), th"
                   L"is indicates  that the note conversion generated a note value that is below 0,  so it has been bumped"
                   L" up one or more octaves to be in the proper MIDI range of 0 through 127.  Note that this is valid for"
                   L" MIDIToMusic() when using play modes DMUS_PLAYMODE_FIXEDTOCHORD and DMUS_PLAYMODE_FIXEDTOKEY, both of"
                   L" which store MIDI values in wMusicValue. With MusicToMIDI(), it is valid for all play modes. Ofcourse"
                   L", DMUS_PLAYMODE_FIXED will never return this success code.";
        }
        return L"n/a";
      }
      switch ( a1 )
      {
        case 142086677:
          return L"Although the audio output from the port will be routed to the same device as the given DirectSound buff"
                 L"er, buffer controls such as pan and volume will not affect the output.";
        case 142086678:
          return L"The requested operation was not performed because during CollectGarbage the loader determined that the "
                 L"object had been released.";
        case 142213121:
          return L"The target window or output has been occluded. The application should suspend rendering operations if possible.";
      }
      return L"n/a";
    }
    if ( a1 == -2005396959 )
      return L"The file contains an invalid lyrics track.";
    if ( a1 > -2005397240 )
    {
      switch ( a1 )
      {
        case -2005397239:
          result = L"Wave chunks in DLS collection file are at incorrect offsets.";
          break;
        case -2005397231:
          result = L"Second attempt to load a DLS collection that is currently open. ";
          break;
        case -2005397229:
          result = L"Error reading wave data from DLS collection. Indicates bad file.";
          break;
        case -2005397228:
          result = L"There is no instrument in the collection that matches patch number.";
          break;
        case -2005397227:
          result = L"The IStream* doesn't support Seek().";
          break;
        case -2005397226:
          result = L"The IStream* doesn't support Write().";
          break;
        case -2005397225:
          result = L"The RIFF parser doesn't contain a required chunk while parsing file.";
          break;
        case -2005397223:
          result = L"Invalid download id was used in the process of creating a download buffer.";
          break;
        case -2005397216:
          result = L"Tried to unload an object that was not downloaded or previously unloaded.";
          break;
        case -2005397215:
          result = L"Buffer was already downloaded to synth.";
          break;
        case -2005397214:
          result = L"The specified property item was not recognized by the target object.";
          break;
        case -2005397213:
          result = L"The specified property item may not be set on the target object.";
          break;
        case -2005397212:
          result = L"* The specified property item may not be retrieved from the target object.";
          break;
        case -2005397211:
          result = L"Wave chunk has more than one interleaved channel. DLS format requires MONO.";
          break;
        case -2005397210:
          result = L"Invalid articulation chunk in DLS collection.";
          break;
        case -2005397209:
          result = L"Invalid instrument chunk in DLS collection.";
          break;
        case -2005397208:
          result = L"Wavelink chunk in DLS collection points to invalid wave.";
          break;
        case -2005397207:
          result = L"Articulation missing from instrument in DLS collection.";
          break;
        case -2005397206:
          result = L"Downoaded DLS wave is not in PCM format. ";
          break;
        case -2005397205:
          result = L"Bad wave chunk in DLS collection";
          break;
        case -2005397204:
          result = L"Offset Table for download buffer has errors. ";
          break;
        case -2005397203:
          result = L"Attempted to download unknown data type.";
          break;
        case -2005397202:
          result = L"The operation could not be completed because no sink was connected to the synthesizer.";
          break;
        case -2005397201:
          result = L"An attempt was made to open the software synthesizer while it was already  open.";
          break;
        case -2005397200:
          result = L"An attempt was made to close the software synthesizer while it was already  open.";
          break;
        case -2005397199:
          result = L"The operation could not be completed because the software synth has not  yet been fully configured.";
          break;
        case -2005397198:
          result = L"The operation cannot be carried out while the synthesizer is active.";
          break;
        case -2005397197:
          result = L"An error occurred while attempting to read from the IStream* object.";
          break;
        case -2005397196:
          result = L"The operation cannot be performed because the final instance of the DirectMusic object was released. "
                   L"Ports cannot be used after final  release of the DirectMusic object.";
          break;
        case -2005397195:
          result = L"There was no data in the referenced buffer.";
          break;
        case -2005397194:
          result = L"There is insufficient space to insert the given event into the buffer.";
          break;
        case -2005397193:
          result = L"The given operation could not be carried out because the port is a capture port.";
          break;
        case -2005397192:
          result = L"The given operation could not be carried out because the port is a render port.";
          break;
        case -2005397191:
          result = L"The port could not be created because no DirectSound has been specified. Specify a DirectSound interf"
                   L"ace via the IDirectMusic::SetDirectSound method; pass NULL to have DirectMusic manage usage of DirectSound.";
          break;
        case -2005397190:
          result = L"The operation cannot be carried out while the port is active.";
          break;
        case -2005397189:
          result = L"Invalid DirectSound buffer was handed to port. ";
          break;
        case -2005397188:
          result = L"Invalid buffer format was handed to the synth sink.";
          break;
        case -2005397187:
          result = L"The operation cannot be carried out while the synthesizer is inactive.";
          break;
        case -2005397186:
          result = L"IDirectMusic::SetDirectSound has already been called. It may not be changed while in use.";
          break;
        case -2005397185:
          result = L"The given event is invalid (either it is not a valid MIDI message or it makes use of running status)."
                   L" The event cannot be packed into the buffer.";
          break;
        case -2005397168:
          result = L"The IStream* object does not contain data supported by the loading object.";
          break;
        case -2005397167:
          result = L"The object has already been initialized.";
          break;
        case -2005397166:
          result = L"The file does not contain a valid band.";
          break;
        case -2005397163:
          result = L"The IStream* object's data does not have a track header as the first chunk, and therefore can not be "
                   L"read by the segment object.";
          break;
        case -2005397162:
          result = L"The IStream* object's data does not have a tool header as the first chunk, and therefore can not be r"
                   L"ead by the graph object.";
          break;
        case -2005397161:
          result = L"The IStream* object's data contains an invalid track header (ckid is 0 and fccType is NULL,) and ther"
                   L"efore can not be read by the segment object.";
          break;
        case -2005397160:
          result = L"The IStream* object's data contains an invalid tool header (ckid is 0 and fccType is NULL,) and there"
                   L"fore can not be read by the graph object.";
          break;
        case -2005397159:
          result = L"The graph object was unable to load all tools from the IStream* object data. This may be due to error"
                   L"s in the stream, or the tools being incorrectly registered on the client.";
          break;
        case -2005397152:
          result = L"The segment object was unable to load all tracks from the IStream* object data. This may be due to er"
                   L"rors in the stream, or the tracks being incorrectly registered on the client.";
          break;
        case -2005397151:
          result = L"The object requested was not found (numerically equal to DMUS_E_NOT_FOUND)";
          break;
        case -2005397150:
          result = L"A required object is not initialized or failed to initialize.";
          break;
        case -2005397149:
          result = L"The requested parameter type is currently disabled. Parameter types may be enabled and disabled by ce"
                   L"rtain calls to SetParam().";
          break;
        case -2005397148:
          result = L"The requested parameter type is not supported on the object.";
          break;
        case -2005397147:
          result = L"The time is in the past, and the operation can not succeed.";
          break;
        case -2005397146:
          result = L"The requested track is not contained by the segment.";
          break;
        case -2005397145:
          result = L"The track does not support clock time playback or getparam.";
          break;
        case -2005397136:
          result = L"There is no master clock in the performance. Be sure to call IDirectMusicPerformance::Init().";
          break;
        case -2005397120:
          result = L"The class id field is required and missing in the DMUS_OBJECTDESC.";
          break;
        case -2005397119:
          result = L"The requested file path is invalid.";
          break;
        case -2005397118:
          result = L"File open failed - either file doesn't exist or is locked.";
          break;
        case -2005397117:
          result = L"Search data type is not supported.";
          break;
        case -2005397116:
          result = L"Unable to find or create object.";
          break;
        case -2005397115:
          result = L"Object was not found.";
          break;
        case -2005397114:
          result = L"The file name is missing from the DMUS_OBJECTDESC.";
          break;
        case -2005396992:
          result = L"The file requested is not a valid file.";
          break;
        case -2005396991:
          result = L"The tool is already contained in the graph. Create a new instance.";
          break;
        case -2005396990:
          result = L"Value is out of range, for instance the requested length is longer than the segment.";
          break;
        case -2005396989:
          result = L"Segment initialization failed, most likely due to a critical memory situation.";
          break;
        case -2005396988:
          result = L"The DMUS_PMSG has already been sent to the performance object via IDirectMusicPerformance::SendPMsg().";
          break;
        case -2005396987:
          result = L"The DMUS_PMSG was either not allocated by the performance via IDirectMusicPerformance::AllocPMsg(), o"
                   L"r it was already freed via IDirectMusicPerformance::FreePMsg().";
          break;
        case -2005396986:
          result = L"The default system port could not be opened.";
          break;
        case -2005396985:
          result = L"A call to MIDIToMusic() or MusicToMIDI() resulted in an error because the requested conversion could "
                   L"not happen. This usually occurs when the provided DMUS_CHORD_KEY structure has an invalid chord or scale pattern.";
          break;
        case -2005396976:
          result = L"DMUS_E_DESCEND_CHUNK_FAIL is returned when the end of the file  was reached before the desired chunk was found.";
          break;
        case -2005396975:
          result = L"An attempt to use this object failed because it first needs to be loaded.";
          break;
        case -2005396973:
          result = L"The activeX scripting engine for the script's language is not compatible with DirectMusic.";
          break;
        case -2005396972:
          result = L"A varient was used that had a type that is not supported by DirectMusic.";
          break;
        case -2005396971:
          result = L"An error was encountered while parsing or executing the script. The pErrorInfo parameter (if supplied"
                   L") was filled with information about the error.";
          break;
        case -2005396970:
          result = L"Loading of oleaut32.dll failed.  VBScript and other activeX scripting languages require use of oleaut"
                   L"32.dll.  On platforms where oleaut32.dll is not present, only the DirectMusicScript language, which d"
                   L"oesn't require oleaut32.dll can be used.";
          break;
        case -2005396969:
          result = L"An error occured while parsing a script loaded using LoadScript.  The script that was loaded contains an error.";
          break;
        case -2005396968:
          result = L"The script file is invalid.";
          break;
        case -2005396967:
          result = L"The file contains an invalid script track.";
          break;
        case -2005396966:
          result = L"The script does not contain a variable with the specified name.";
          break;
        case -2005396965:
          result = L"The script does not contain a routine with the specified name.";
          break;
        case -2005396964:
          result = L"Scripts variables for content referenced or embedded in a script cannot be set.";
          break;
        case -2005396963:
          result = L"Attempt was made to set a script's variable by reference to a value that was not an object type.";
          break;
        case -2005396962:
          result = L"Attempt was made to set a script's variable by value to an object that does not support a default value property.";
          break;
        case -2005396960:
          result = L"The file contains an invalid segment trigger track.";
          break;
        default:
          return L"n/a";
      }
      return result;
    }
    if ( a1 == -2005397240 )
      return L"Error parsing DLS collection. File is corrupt.";
    if ( a1 <= -2005530595 )
    {
      if ( a1 == -2005530595 )
        return L"Too many operations";
      if ( a1 > -2005531771 )
      {
        if ( a1 > -2005530600 )
        {
          switch ( a1 )
          {
            case -2005530599:
              return L"Unsupported color operation";
            case -2005530598:
              return L"Unsupported color arg";
            case -2005530597:
              return L"Unsupported alpha operation";
            default:
              return L"Unsupported alpha arg";
          }
        }
        else if ( a1 == -2005530600 )
        {
          return L"Wrong texture format";
        }
        else
        {
          switch ( a1 )
          {
            case -2005531770:
              result = L"Bad type";
              break;
            case -2005531769:
              return L"Not found";
            case -2005531768:
              result = L"Not done yet";
              break;
            case -2005531767:
              result = L"File not found";
              break;
            case -2005531766:
              result = L"Resource not found";
              break;
            case -2005531765:
              result = L"Bad resource";
              break;
            case -2005531764:
              result = L"Bad file type";
              break;
            case -2005531763:
              result = L"Bad file version";
              break;
            case -2005531762:
              result = L"Bad file float size";
              break;
            case -2005531761:
              result = L"Bad file";
              break;
            case -2005531760:
              result = L"Parse error";
              break;
            case -2005531759:
LABEL_679:
              result = L"Bad array size";
              break;
            case -2005531758:
LABEL_680:
              result = L"Bad data reference";
              break;
            case -2005531757:
LABEL_681:
              result = L"No more objects";
              break;
            case -2005531756:
LABEL_682:
              result = L"No more data";
              break;
            case -2005531755:
LABEL_683:
              result = L"Bad cache file";
              break;
            default:
              return L"n/a";
          }
        }
      }
      else
      {
        if ( a1 == -2005531771 )
          return L"Bad value";
        if ( a1 <= -2005531973 )
        {
          if ( a1 == -2005531973 )
            return L"Surfaces created by one direct draw device cannot be used directly by another direct draw device.";
          if ( a1 > -2005531980 )
          {
            switch ( a1 )
            {
              case -2005531979:
                return L"The mode test has switched to a new mode.";
              case -2005531978:
                return L"D3D has not yet been initialized.";
              case -2005531977:
                return L"The video port is not active";
              case -2005531976:
                return L"The monitor does not have EDID data.";
              case -2005531975:
                return L"The driver does not enumerate display mode refresh rates.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2005531980:
                return L"The mode test has finished executing.";
              case -2005532032:
                return L"The attempt to page lock a surface failed.";
              case -2005532012:
                return L"The attempt to page unlock a surface failed.";
              case -2005531992:
                return L"An attempt was made to page unlock a surface with no outstanding page locks.";
              case -2005531982:
                return L"There is more data available than the specified buffer size could hold";
              case -2005531981:
                return L"The data has expired and is therefore no longer valid.";
            }
          }
          return L"n/a";
        }
        if ( a1 == -2005531772 )
        {
          return L"Bad object";
        }
        else
        {
          switch ( a1 )
          {
            case -2005531804:
              goto LABEL_679;
            case -2005531803:
              goto LABEL_680;
            case -2005531802:
              result = L"Internal error";
              break;
            case -2005531801:
              goto LABEL_681;
            case -2005531800:
              result = L"Bad intrinsics";
              break;
            case -2005531799:
              result = L"No more stream handles";
              break;
            case -2005531798:
              goto LABEL_682;
            case -2005531797:
              goto LABEL_683;
            case -2005531796:
              result = L"No internet";
              break;
            default:
              return L"n/a";
          }
        }
      }
      return result;
    }
    if ( a1 <= -2005529765 )
    {
      if ( a1 == -2005529765 )
        return L"Duplicate named fragment";
      if ( a1 <= -2005530518 )
      {
        if ( a1 == -2005530518 )
          return L"Not available";
        if ( a1 > -2005530585 )
        {
          switch ( a1 )
          {
            case -2005530522:
              return L"Not found";
            case -2005530521:
              return L"More data";
            case -2005530520:
              return L"Device lost";
            case -2005530519:
              return L"Device not reset";
          }
        }
        else
        {
          switch ( a1 )
          {
            case -2005530585:
              return L"Driver internal error";
            case -2005530594:
              return L"Conflicting texture filter";
            case -2005530593:
              return L"Unsupported factor value";
            case -2005530591:
              return L"Conflicting render state";
            case -2005530590:
              return L"Unsupported texture filter";
            case -2005530586:
              return L"Conflicting texture palette";
          }
        }
        return L"n/a";
      }
      if ( a1 <= -2005529770 )
      {
        switch ( a1 )
        {
          case -2005529770:
            return L"Cannot attr sort";
          case -2005530517:
            return L"Invalid device";
          case -2005530516:
            return L"Invalid call";
          case -2005530515:
            return L"Driver invalid call";
          case -2005529772:
            return L"Can not modify index buffer";
          case -2005529771:
            return L"Invalid mesh";
        }
        return L"n/a";
      }
      switch ( a1 )
      {
        case -2005529769:
          return L"Skinning not supported";
        case -2005529768:
          return L"Too many influences";
        case -2005529767:
          return L"Invalid data";
      }
      return L"Loaded mesh has no data";
    }
    if ( a1 > -2005401430 )
    {
      if ( a1 > -2005397246 )
      {
        switch ( a1 )
        {
          case -2005397245:
            return L"The requested device is already in use (possibly by a non-DirectMusic client) and cannot be opened again.";
          case -2005397244:
            return L"Buffer is not large enough for requested operation.";
          case -2005397243:
            return L"No buffer was prepared for the download data.";
          case -2005397242:
            return L"Download failed due to inability to access or create download buffer.";
        }
      }
      else
      {
        switch ( a1 )
        {
          case -2005397246:
            return L"The requested operation cannot be performed while there are  instantiated ports in any process in the system.";
          case -2005401420:
            return L"Tried to create a DSBCAPS_CTRLFX buffer shorter than DSBSIZE_FX_MIN milliseconds";
          case -2005401410:
            return L"Attempt to use DirectSound 8 functionality on an older DirectSound object";
          case -2005401400:
            return L"A circular loop of send effects was detected";
          case -2005401390:
            return L"The GUID specified in an audiopath file does not match a valid MIXIN buffer";
          case -2005397247:
            return L"An unexpected error was returned from a device driver, indicating possible failure of the driver or hardware.";
        }
      }
      return L"n/a";
    }
    if ( a1 == -2005401430 )
      return L"This object has not been initialized";
    if ( a1 <= -2005401500 )
    {
      switch ( a1 )
      {
        case -2005401500:
          return L"The specified WAVE format is not supported";
        case -2005529764:
          return L"Can Not remove last item";
        case -2005401590:
          return L"The call failed because resources (such as a priority level) were already being used by another caller";
        case -2005401570:
          return L"The control (vol, pan, etc.) requested by the caller is not available";
        case -2005401550:
          return L"This call is not valid for the current state of this object";
        case -2005401530:
          return L"The caller does not have the priority level required for the function to succeed";
      }
      return L"n/a";
    }
    if ( a1 == -2005401480 )
      return L"No sound driver is available for use";
    if ( a1 != -2005401470 )
    {
      if ( a1 == -2005401450 )
        return L"The buffer memory has been lost, and must be restored";
      if ( a1 == -2005401440 )
        return L"Another app has a higher priority level, preventing this call from succeeding";
      return L"n/a";
    }
    return L"This object is already initialized";
  }
  if ( a1 == -2005532092 )
    return L"returned when an overlay member is called for a non-overlay surface";
  if ( a1 > -2146107092 )
  {
    if ( a1 > -2146073232 )
    {
      if ( a1 > -2005532342 )
      {
        if ( a1 <= -2005532135 )
        {
          if ( a1 == -2005532135 )
            return L"vertical blank is in progress";
          if ( a1 > -2005532242 )
          {
            if ( a1 > -2005532192 )
            {
              switch ( a1 )
              {
                case -2005532182:
                  return L"Width requested by DirectDraw is too large.";
                case -2005532162:
                  return L"Pixel format requested is unsupported by DirectDraw";
                case -2005532152:
                  return L"Bitmask in the pixel format requested is unsupported by DirectDraw";
                case -2005532151:
                  return L"The specified stream contains invalid data";
              }
            }
            else
            {
              switch ( a1 )
              {
                case -2005532192:
                  return L"Size requested by DirectDraw is too large --  The individual height and width are OK.";
                case -2005532237:
                  return L"Access to this surface is being refused because no driver exists which can supply a pointer to "
                         L"the surface. This is most likely to happen when attempting to lock the primary surface when no "
                         L"DCI provider is present. Will also happen on attempts to lock an optimized surface.";
                case -2005532232:
                  return L"Access to Surface refused because Surface is obscured.";
                case -2005532222:
                  return L"Access to this surface is being refused because the surface is gone. The DIRECTDRAWSURFACE obje"
                         L"ct representing this surface should have Restore called on it.";
                case -2005532212:
                  return L"The requested surface is not attached.";
                case -2005532202:
                  return L"Height requested by DirectDraw is too large.";
              }
            }
          }
          else
          {
            if ( a1 == -2005532242 )
              return L"Access to this surface is being refused because the surface is already locked by another thread.";
            if ( a1 > -2005532290 )
            {
              switch ( a1 )
              {
                case -2005532288:
                  return L"Can only have ony color key active at one time for overlays";
                case -2005532285:
                  return L"Access to this palette is being refused because the palette is already locked by another thread.";
                case -2005532272:
                  return L"No src color key specified for this operation.";
                case -2005532262:
                  return L"This surface is already attached to the surface it is being attached to.";
                case -2005532252:
                  return L"This surface is already a dependency of the surface it is being made a dependency of.";
              }
            }
            else
            {
              switch ( a1 )
              {
                case -2005532290:
                  return L"hardware does not support clipped overlays";
                case -2005532337:
                  return L"Operation could not be carried out because there is no hardware support for vertical blank sync"
                         L"hronized operations.";
                case -2005532332:
                  return L"Operation could not be carried out because there is no hardware support for zbuffer blting.";
                case -2005532322:
                  return L"Overlay surfaces could not be z layered based on their BltOrder because the hardware does not s"
                         L"upport z layering of overlays.";
                case -2005532312:
                  return L"The hardware needed for the requested operation has already been allocated.";
                case -2005532292:
                  return L"Out of video memory";
              }
            }
          }
          return L"n/a";
        }
        switch ( a1 )
        {
          case -2005532132:
            result = L"Was still drawing";
            break;
          case -2005532130:
            result = L"The specified surface type requires specification of the COMPLEX flag";
            break;
          case -2005532112:
            result = L"Rectangle provided was not horizontally aligned on reqd. boundary";
            break;
          case -2005532111:
            result = L"The GUID passed to DirectDrawCreate is not a valid DirectDraw driver identifier.";
            break;
          case -2005532110:
            result = L"A DirectDraw object representing this driver has already been created for this process.";
            break;
          case -2005532109:
            result = L"A hardware only DirectDraw object creation was attempted but the driver did not support any hardware.";
            break;
          case -2005532108:
            result = L"this process already has created a primary surface";
            break;
          case -2005532107:
            result = L"software emulation not available.";
            break;
          case -2005532106:
            result = L"region passed to Clipper::GetClipList is too small.";
            break;
          case -2005532105:
            result = L"an attempt was made to set a clip list for a clipper objec that is already monitoring an hwnd.";
            break;
          case -2005532104:
            result = L"No clipper object attached to surface object";
            break;
          case -2005532103:
            result = L"Clipper notification requires an HWND or no HWND has previously been set as the CooperativeLevel HWND.";
            break;
          case -2005532102:
            result = L"HWND used by DirectDraw CooperativeLevel has been subclassed, this prevents DirectDraw from restoring state.";
            break;
          case -2005532101:
            result = L"The CooperativeLevel HWND has already been set. It can not be reset while the process has surfaces "
                     L"or palettes created.";
            break;
          case -2005532100:
            result = L"No palette object attached to this surface.";
            break;
          case -2005532099:
            result = L"No hardware support for 16 or 256 color palettes.";
            break;
          case -2005532098:
            result = L"If a clipper object is attached to the source surface passed into a BltFast call.";
            break;
          case -2005532097:
            result = L"No blter.";
            break;
          case -2005532096:
            result = L"No DirectDraw ROP hardware.";
            break;
          case -2005532095:
            result = L"returned when GetOverlayPosition is called on a hidden overlay";
            break;
          case -2005532094:
            result = L"returned when GetOverlayPosition is called on a overlay that UpdateOverlay has never been called on"
                     L" to establish a destionation.";
            break;
          case -2005532093:
            result = L"returned when the position of the overlay on the destionation is no longer legal for that destionation.";
            break;
          default:
            return L"n/a";
        }
        return result;
      }
      if ( a1 == -2005532342 )
        return L"Operation could not be carried out because there is no texture mapping hardware present or available.";
      if ( a1 > -2005532502 )
      {
        if ( a1 > -2005532432 )
        {
          if ( a1 > -2005532382 )
          {
            switch ( a1 )
            {
              case -2005532362:
                return L"Operation could not be carried out because there is no hardware support for stretching";
              case -2005532356:
                return L"DirectDrawSurface is not in 4 bit color palette and the requested operation requires 4 bit color palette.";
              case -2005532355:
                return L"DirectDrawSurface is not in 4 bit color index palette and the requested operation requires 4 bit "
                       L"color index palette.";
              case -2005532352:
                return L"DirectDraw Surface is not in 8 bit color mode and the requested operation requires 8 bit color.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2005532382:
                return L"Operation could not be carried out because there is no rotation hardware present or available.";
              case -2005532422:
                return L"Operation could not be carried out because there is no hardware present or available.";
              case -2005532417:
                return L"Requested item was not found";
              case -2005532412:
                return L"Operation could not be carried out because there is no overlay hardware present or available.";
              case -2005532402:
                return L"Operation could not be carried out because the source and destination rectangles are on the same "
                       L"surface and overlap each other.";
              case -2005532392:
                return L"Operation could not be carried out because there is no appropriate raster op hardware present or available.";
            }
          }
        }
        else
        {
          if ( a1 == -2005532432 )
            return L"There is no GDI present.";
          if ( a1 > -2005532460 )
          {
            switch ( a1 )
            {
              case -2005532457:
                return L"Surface doesn't currently have a color key";
              case -2005532452:
                return L"Operation could not be carried out because there is no hardware support of the dest color key.";
              case -2005532450:
                return L"No DirectDraw support possible with current display driver";
              case -2005532447:
                return L"Operation requires the application to have exclusive mode but the application does not have exclusive mode.";
              case -2005532442:
                return L"Flipping visible surfaces is not supported.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2005532460:
                return L"Create function called without DirectDraw object method SetCooperativeLevel being called.";
              case -2005532492:
                return L"Operation could not be carried out because there is no alpha accleration hardware present or available.";
              case -2005532491:
                return L"Operation could not be carried out because there is no stereo hardware present or available.";
              case -2005532490:
                return L"Operation could not be carried out because there is no hardware present which supports stereo surfaces";
              case -2005532467:
                return L"no clip list available";
              case -2005532462:
                return L"Operation could not be carried out because there is no color conversion hardware present or available.";
            }
          }
        }
        return L"n/a";
      }
      if ( a1 == -2005532502 )
        return L"There is no 3D present.";
      if ( a1 > -2005532632 )
      {
        if ( a1 > -2005532552 )
        {
          switch ( a1 )
          {
            case -2005532542:
              return L"DirectDraw received a pointer that was an invalid DIRECTDRAW object.";
            case -2005532527:
              return L"pixel format was invalid as specified";
            case -2005532522:
              return L"Rectangle provided was invalid.";
            case -2005532512:
              return L"Operation could not be carried out because one or more surfaces are locked";
          }
        }
        else
        {
          switch ( a1 )
          {
            case -2005532552:
              return L"DirectDraw does not support the requested mode";
            case -2005532617:
              return L"An exception was encountered while performing the requested operation";
            case -2005532582:
              return L"Height of rectangle provided is not a multiple of reqd alignment";
            case -2005532577:
              return L"Unable to match primary surface creation request with existing primary surface.";
            case -2005532572:
              return L"One or more of the caps bits passed to the callback are incorrect.";
            case -2005532562:
              return L"DirectDraw does not support provided Cliplist.";
          }
        }
        return L"n/a";
      }
      if ( a1 == -2005532632 )
        return L"Support is currently not available.";
      if ( a1 <= -2146073040 )
      {
        switch ( a1 )
        {
          case -2146073040:
            return L"Timed out";
          case -2146073216:
            return L"Player not in group";
          case -2146073200:
            return L"Player not reachable";
          case -2146073088:
            return L"Send too large";
          case -2146073072:
            return L"Session full";
          case -2146073056:
            return L"Table full";
        }
        return L"n/a";
      }
      if ( a1 == -2146073024 )
        return L"Uninitialized";
      if ( a1 != -2146073008 )
      {
        if ( a1 != -2005532667 )
        {
          if ( a1 == -2005532662 )
            return L"This surface can not be attached to the requested surface.";
          if ( a1 == -2005532652 )
            return L"This surface can not be detached from the requested surface.";
          return L"n/a";
        }
        return L"This object is already initialized";
      }
    }
    else
    {
      if ( a1 == -2146073232 )
        return L"Player lost";
      if ( a1 > -2146074320 )
      {
        if ( a1 <= -2146073792 )
        {
          if ( a1 != -2146073792 )
          {
            if ( a1 > -2146074064 )
            {
              if ( a1 > -2146073968 )
              {
                switch ( a1 )
                {
                  case -2146073856:
                    return L"Invalid application";
                  case -2146073840:
                    return L"Invalid command";
                  case -2146073824:
                    return L"Invalid device address";
                  case -2146073808:
                    return L"Invalid end point";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -2146073968:
                    return L"Invalid address format";
                  case -2146074048:
                    return L"Group not empty";
                  case -2146074032:
                    return L"Hosting";
                  case -2146074016:
                    return L"Host rejected connection";
                  case -2146074000:
                    return L"Host terminated session";
                  case -2146073984:
                    return L"Incomplete address";
                }
              }
              return L"n/a";
            }
            if ( a1 != -2146074064 )
            {
              if ( a1 > -2146074240 )
              {
                switch ( a1 )
                {
                  case -2146074235:
                    return L"dpnsvr not available";
                  case -2146074224:
                    return L"Duplicate command";
                  case -2146074112:
                    return L"End point not receiving";
                  case -2146074096:
                    return L"Enum query too large";
                  case -2146074080:
                    return L"Enum response too large";
                }
              }
              else
              {
                switch ( a1 )
                {
                  case -2146074240:
                    return L"Does not exist";
                  case -2146074304:
                    return L"Cant launch application";
                  case -2146074288:
                    return L"Connecting";
                  case -2146074272:
                    return L"Connection lost";
                  case -2146074256:
                    return L"Conversion";
                  case -2146074251:
                    return L"Data too large";
                }
              }
              return L"n/a";
            }
            return L"Exception";
          }
          return L"Invalid flags";
        }
        if ( a1 > -2146073504 )
        {
          if ( a1 > -2146073312 )
          {
            switch ( a1 )
            {
              case -2146073296:
                return L"Not host";
              case -2146073280:
                return L"Not ready";
              case -2146073264:
                return L"Not registered";
              case -2146073248:
                return L"Player already in group";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2146073312:
                return L"Not allowed";
              case -2146073488:
                return L"No caps";
              case -2146073472:
                return L"No connection";
              case -2146073456:
                return L"No host player";
              case -2146073344:
                return L"No more address components";
              case -2146073328:
                return L"No response";
            }
          }
          return L"n/a";
        }
        if ( a1 == -2146073504 )
          return L"Invalid version";
        if ( a1 > -2146073600 )
        {
          if ( a1 == -2146073584 )
            return L"Invalid password";
          if ( a1 != -2146073568 )
          {
            switch ( a1 )
            {
              case -2146073552:
                return L"Invalid priority";
              case -2146073536:
                return L"Invalid string";
              case -2146073520:
                return L"Invalid url";
            }
            return L"n/a";
          }
          return L"Invalid player";
        }
        if ( a1 != -2146073600 )
        {
          if ( a1 != -2146073776 )
          {
            if ( a1 != -2146073760 )
            {
              switch ( a1 )
              {
                case -2146073744:
                  return L"Invalid host address";
                case -2146073728:
                  return L"Invalid instance";
                case -2146073712:
                  return L"Invalid interface";
              }
              return L"n/a";
            }
            return L"Invalid handle";
          }
          return L"Invalid group";
        }
        return L"Invalid object";
      }
      if ( a1 == -2146074320 )
        return L"Cant create player";
      if ( a1 > -2146107008 )
      {
        if ( a1 <= -2146074576 )
        {
          if ( a1 == -2146074576 )
            return L"Aborted";
          switch ( a1 )
          {
            case -2146107005:
              result = L"Run setup";
              break;
            case -2146107004:
              result = L"Incompatible version";
              break;
            case -2146107001:
              result = L"Initialized";
              break;
            case -2146107000:
              result = L"No transport";
              break;
            case -2146106999:
              result = L"No callback";
              break;
            case -2146106998:
              result = L"Transport not init";
              break;
            case -2146106997:
              result = L"Transport no session";
              break;
            case -2146106996:
              result = L"Transport no player";
              break;
            case -2146106995:
              result = L"User back";
              break;
            case -2146106994:
              result = L"No rec vol available";
              break;
            case -2146106993:
              result = L"Invalid buffer";
              break;
            case -2146106992:
              result = L"Locked buffer";
              break;
            default:
              return L"n/a";
          }
          return result;
        }
        if ( a1 <= -2146074496 )
        {
          switch ( a1 )
          {
            case -2146074496:
              return L"Already initialized";
            case -2146074560:
              return L"Addressing";
            case -2146074544:
              return L"Already closing";
            case -2146074528:
              return L"Already connected";
            case -2146074512:
              return L"Already disconnecting";
          }
          return L"n/a";
        }
        if ( a1 == -2146074480 )
          return L"Already registered";
        if ( a1 != -2146074368 )
        {
          if ( a1 == -2146074352 )
            return L"Can not cancel";
          if ( a1 == -2146074336 )
            return L"Cant create group";
          return L"n/a";
        }
        return L"Buffer too small";
      }
      if ( a1 != -2146107008 )
      {
        switch ( a1 )
        {
          case -2146107090:
            result = L"No voice session";
            break;
          case -2146107032:
            return L"Connection lost";
          case -2146107031:
            result = L"Not initialized";
            break;
          case -2146107030:
            result = L"Connected";
            break;
          case -2146107029:
            result = L"Not connected";
            break;
          case -2146107026:
            result = L"Connect aborting";
            break;
          case -2146107025:
            return L"Not allowed";
          case -2146107024:
            result = L"Invalid target";
            break;
          case -2146107023:
            result = L"Transport not host";
            break;
          case -2146107022:
            result = L"Compression not supported";
            break;
          case -2146107021:
            result = L"Already pending";
            break;
          case -2146107020:
            result = L"Sound init failure";
            break;
          case -2146107019:
            result = L"Time out";
            break;
          case -2146107018:
            result = L"Connect aborted";
            break;
          case -2146107017:
            result = L"No 3d sound";
            break;
          case -2146107016:
            result = L"Already buffered";
            break;
          case -2146107015:
            result = L"Not buffered";
            break;
          case -2146107014:
            return L"Hosting";
          case -2146107013:
            result = L"Not hosting";
            break;
          case -2146107012:
            return L"Invalid device";
          case -2146107011:
            result = L"Record system error";
            break;
          case -2146107010:
            result = L"Playback system error";
            break;
          case -2146107009:
            result = L"Send error";
            break;
          default:
            return L"n/a";
        }
        return result;
      }
    }
    return L"User cancel";
  }
  if ( a1 == -2146107092 )
    return L"Session lost";
  if ( a1 > -2147220890 )
  {
    if ( a1 <= -2147220476 )
    {
      if ( a1 == -2147220476 )
        return L"Seeking not supported for this object.";
      if ( a1 > -2147220855 )
      {
        if ( a1 > -2147220736 )
        {
          if ( a1 > -2147220494 )
          {
            switch ( a1 )
            {
              case -2147220481:
                return L"Device installer errors.";
              case -2147220480:
                return L"Registry entry or DLL for class installer invalid or class installer not found.";
              case -2147220479:
                return L"The user cancelled the install operation. & The stream already has allocated samples and the surf"
                       L"ace doesn't match the sample format.";
              case -2147220478:
                return L"The INF file for the selected device could not be found or is invalid or is damaged. & The specif"
                       L"ied purpose ID can't be used for the call.";
              case -2147220477:
                return L"No stream can be found with the specified attributes.";
            }
          }
          else
          {
            switch ( a1 )
            {
              case -2147220494:
                return L"A registry entry is corrupt.";
              case -2147220735:
                return L"DIERR_DRIVERFIRST+1";
              case -2147220734:
                return L"DIERR_DRIVERFIRST+2";
              case -2147220733:
                return L"DIERR_DRIVERFIRST+3";
              case -2147220732:
                return L"DIERR_DRIVERFIRST+4";
              case -2147220731:
                return L"DIERR_DRIVERFIRST+5";
            }
          }
          return L"n/a";
        }
        if ( a1 == -2147220736 )
        {
          return L"Device driver-specific codes. Unless the specific driver has been precisely identified, no meaning shou"
                 L"ld be attributed to these values other than that the driver originated the error.";
        }
        else
        {
          switch ( a1 )
          {
            case -2147220854:
              result = L"The current parental level was too low.";
              break;
            case -2147220853:
              result = L"The current audio is not karaoke content.";
              break;
            case -2147220850:
              result = L"Frame step is not supported on this configuration.";
              break;
            case -2147220849:
              result = L"The specified stream is disabled and cannot be selected.";
              break;
            case -2147220848:
              result = L"The operation depends on the current title number, however the navigator has not yet entered the "
                       L"VTSM or the title domains, so the 'current' title index is unknown.";
              break;
            case -2147220847:
              result = L"The specified path does not point to a valid DVD disc.";
              break;
            case -2147220846:
              result = L"There is currently no resume information.";
              break;
            case -2147220845:
              result = L"This thread has already blocked this output pin.  There is no need to call IPinFlowControl::Block() again.";
              break;
            case -2147220844:
              result = L"IPinFlowControl::Block() has been called on another thread.  The current thread cannot make any a"
                       L"ssumptions about this pin's block state.";
              break;
            case -2147220843:
              result = L"An operation failed due to a certification failure.";
              break;
            default:
              return L"n/a";
          }
        }
      }
      else if ( a1 == -2147220855 )
      {
        return L"Currently there is no GoUp (Annex J user function) program chain (PGC).";
      }
      else
      {
        switch ( a1 )
        {
          case -2147220887:
            result = L"The Video CD can't be read correctly by the device or is the data is corrupt.";
            break;
          case -2147220879:
            result = L"There is not enough Video Memory at this display resolution and number of colors. Reducing resolution might help.";
            break;
          case -2147220878:
            result = L"The VideoPort connection negotiation process has failed.";
            break;
          case -2147220877:
            result = L"Either DirectDraw has not been installed or the Video Card capabilities are not suitable. Make sure"
                     L" the display is not in 16 color mode.";
            break;
          case -2147220876:
            result = L"No VideoPort hardware is available, or the hardware is not responding.";
            break;
          case -2147220875:
            result = L"No Capture hardware is available, or the hardware is not responding.";
            break;
          case -2147220874:
            result = L"This User Operation is inhibited by DVD Content at this time.";
            break;
          case -2147220873:
            result = L"This Operation is not permitted in the current domain.";
            break;
          case -2147220872:
            result = L"The specified button is invalid or is not present at the current time, or there is no button presen"
                     L"t at the specified location.";
            break;
          case -2147220871:
            result = L"DVD-Video playback graph has not been built yet.";
            break;
          case -2147220870:
            result = L"DVD-Video playback graph building failed.";
            break;
          case -2147220869:
            result = L"DVD-Video playback graph could not be built due to insufficient decoders.";
            break;
          case -2147220868:
            result = L"Version number of DirectDraw not suitable. Make sure to install dx5 or higher version.";
            break;
          case -2147220867:
            result = L"Copy protection cannot be enabled. Please make sure any other copy protected content is not being shown now.";
            break;
          case -2147220865:
            result = L"This object cannot be used anymore as its time has expired.";
            break;
          case -2147220863:
            result = L"The operation cannot be performed at the current playback speed.";
            break;
          case -2147220862:
            result = L"The specified menu doesn't exist.";
            break;
          case -2147220861:
            result = L"The specified command was either cancelled or no longer exists.";
            break;
          case -2147220860:
            result = L"The data did not contain a recognized version.";
            break;
          case -2147220859:
            result = L"The state data was corrupt.";
            break;
          case -2147220858:
            result = L"The state data is from a different disc.";
            break;
          case -2147220857:
            result = L"The region was not compatible with the current drive.";
            break;
          case -2147220856:
            result = L"The requested DVD stream attribute does not exist.";
            break;
          default:
            return L"n/a";
        }
      }
      return result;
    }
    if ( a1 <= -2147024887 )
    {
      if ( a1 == -2147024887 )
        return L"The storage control block address is invalid.";
      if ( a1 <= -2147219194 )
      {
        if ( a1 == -2147219194 )
          return L"An error occurred when attempting to reset a device.";
        if ( a1 > -2147220470 )
        {
          switch ( a1 )
          {
            case -2147219199:
              return L"Could not initialize Direct3D.";
            case -2147219198:
              return L"No device could be found with the specified device settings.";
            case -2147219197:
              return L"A media file could not be found.";
            case -2147219196:
              return L"The device interface has a non-zero reference count, meaning that some objects were not released.";
            case -2147219195:
              return L"An error occurred when attempting to create a device.";
          }
          return L"n/a";
        }
        switch ( a1 )
        {
          case -2147220470:
            return L"The object is not in running state.";
          case -2147220475:
            return L"The stream formats are not compatible.";
          case -2147220474:
            return L"The sample is busy.";
          case -2147220473:
            return L"The object can't accept the call because its initialize function or equivalent has not been called.";
          case -2147220472:
            return L"MS_E_SOURCEALREADYDEFINED";
        }
        return L"The stream type is not valid for this operation.";
      }
      if ( a1 <= -2147024893 )
      {
        switch ( a1 )
        {
          case -2147024893:
            return L"The system cannot find the path specified.";
          case -2147219193:
            return L"An error occurred in the device create callback function.";
          case -2147219192:
            return L"An error occurred in the device reset callback function.";
          case -2147219191:
            return L"Incorrect version of Direct3D or D3DX.";
          case -2147219190:
            return L"The device was removed.";
          case -2147024894:
            return L"The system cannot find the file specified.";
        }
        return L"n/a";
      }
      if ( a1 == -2147024892 )
        return L"The system cannot open the file.";
      if ( a1 == -2147024891 )
        return L"Access is denied";
      if ( a1 != -2147024890 )
      {
        if ( a1 == -2147024888 )
          return L"Not enough storage is available to process this command.";
        return L"n/a";
      }
      return L"Invalid handle";
    }
    if ( a1 <= -2147023743 )
    {
      if ( a1 == -2147023743 )
        return L"The application was written for an unsupported prerelease version of DirectInput.";
      if ( a1 > -2147024866 )
      {
        switch ( a1 )
        {
          case -2147024809:
            return L"An invalid parameter was passed to the returning function";
          case -2147024777:
            return L"The object could not be created due to an incompatible driver version or mismatched or incomplete driver components.";
          case -2147024726:
            return L"The operation cannot be performed while the device is acquired.";
          case -2147024637:
            return L"No more items.";
          case -2147023746:
            return L"The application requires a newer version of DirectInput.";
        }
        return L"n/a";
      }
      switch ( a1 )
      {
        case -2147024866:
          return L"Access to the device has been lost.  It must be re-acquired.";
        case -2147024886:
          return L"The environment is incorrect.";
        case -2147024885:
          return L"An attempt was made to load a program with an incorrect format.";
        case -2147024884:
          return L"The operation cannot be performed unless the device is acquired.";
        case -2147024882:
          return L"Ran out of memory";
      }
      if ( a1 != -2147024875 )
        return L"n/a";
      return L"This object has not been initialized";
    }
    if ( a1 <= -2146107272 )
    {
      if ( a1 != -2146107272 )
      {
        if ( a1 == -2147023728 )
          return L"The specified property ID is not supported for the specified property set.";
        if ( a1 == -2147023726 )
          return L"The specified property set is not supported.";
        if ( a1 != -2147023649 )
        {
          if ( a1 != -2146107362 )
          {
            if ( a1 == -2146107318 )
              return L"Exception";
            return L"n/a";
          }
          return L"Buffer too small";
        }
        return L"This object is already initialized";
      }
      return L"Invalid flags";
    }
    if ( a1 != -2146107262 )
    {
      if ( a1 != -2146107257 )
      {
        if ( a1 != -2146107247 )
        {
          if ( a1 == -2146107242 )
            return L"Invalid handle";
          return L"n/a";
        }
        return L"Invalid group";
      }
      return L"Invalid player";
    }
    return L"Invalid object";
  }
  if ( a1 == -2147220890 )
    return L"Pins cannot connect due to not supporting the same transport.";
  if ( a1 > -2147220957 )
  {
    switch ( a1 )
    {
      case -2147220956:
        result = L"The operation could not be performed because the filter is not stopped.";
        break;
      case -2147220955:
        result = L"The operation could not be performed because the filter is not paused.";
        break;
      case -2147220954:
        result = L"The operation could not be performed because the filter is not running.";
        break;
      case -2147220953:
        result = L"The operation could not be performed because the filter is in the wrong state.";
        break;
      case -2147220952:
        result = L"The sample start time is after the sample end time.";
        break;
      case -2147220951:
        result = L"The supplied rectangle is invalid.";
        break;
      case -2147220950:
        result = L"This pin cannot use the supplied media type.";
        break;
      case -2147220949:
        result = L"This sample cannot be rendered.";
        break;
      case -2147220948:
        result = L"This sample cannot be rendered because the end of the stream has been reached.";
        break;
      case -2147220947:
        result = L"An attempt to add a filter with a duplicate name failed.";
        break;
      case -2147220946:
        result = L"A time-out has expired.";
        break;
      case -2147220945:
        result = L"The file format is invalid.";
        break;
      case -2147220944:
        result = L"The list has already been exhausted.";
        break;
      case -2147220943:
        result = L"The filter graph is circular.";
        break;
      case -2147220942:
        result = L"Updates are not allowed in this state.";
        break;
      case -2147220941:
        result = L"An attempt was made to queue a command for a time in the past.";
        break;
      case -2147220940:
        result = L"The queued command has already been canceled.";
        break;
      case -2147220939:
        result = L"Cannot render the file because it is corrupt.";
        break;
      case -2147220938:
        result = L"An overlay advise link already exists.";
        break;
      case -2147220936:
        result = L"No full-screen modes are available.";
        break;
      case -2147220935:
        result = L"This Advise cannot be canceled because it was not successfully set.";
        break;
      case -2147220934:
        result = L"A full-screen mode is not available.";
        break;
      case -2147220933:
        result = L"Cannot call IVideoWindow methods while in full-screen mode.";
        break;
      case -2147220928:
        result = L"The media type of this file is not recognized.";
        break;
      case -2147220927:
        result = L"The source filter for this file could not be loaded.";
        break;
      case -2147220925:
        result = L"A file appeared to be incomplete.";
        break;
      case -2147220924:
        result = L"The version number of the file is invalid.";
        break;
      case -2147220921:
        result = L"This file is corrupt: it contains an invalid class identifier.";
        break;
      case -2147220920:
        result = L"This file is corrupt: it contains an invalid media type.";
        break;
      case -2147220919:
        result = L"No time stamp has been set for this sample.";
        break;
      case -2147220911:
        result = L"No media time stamp has been set for this sample.";
        break;
      case -2147220910:
        result = L"No media time format has been selected.";
        break;
      case -2147220909:
        result = L"Cannot change balance because audio device is mono only.";
        break;
      case -2147220907:
        return L"Cannot play back the video stream: no suitable decompressor could be found.";
      case -2147220906:
        result = L"Cannot play back the audio stream: no audio hardware is available, or the hardware is not responding.";
        break;
      case -2147220903:
        return L"Cannot play back the video stream: format 'RPZA' is not supported.";
      case -2147220901:
        result = L"ActiveMovie cannot play MPEG movies on this processor.";
        break;
      case -2147220900:
        result = L"Cannot play back the audio stream: the audio format is not supported.";
        break;
      case -2147220899:
        result = L"Cannot play back the video stream: the video format is not supported.";
        break;
      case -2147220898:
        result = L"ActiveMovie cannot play this video stream because it falls outside the constrained standard.";
        break;
      case -2147220897:
        result = L"Cannot perform the requested function on an object that is not in the filter graph.";
        break;
      case -2147220895:
        result = L"Cannot get or set time related information on an object that is using a time format of TIME_FORMAT_NONE.";
        break;
      case -2147220894:
        result = L"The connection cannot be made because the stream is read only and the filter alters the data.";
        break;
      case -2147220892:
        result = L"The buffer is not full enough.";
        break;
      case -2147220891:
        result = L"Cannot play back the file.  The format is not supported.";
        break;
      default:
        return L"n/a";
    }
  }
  else
  {
    if ( a1 == -2147220957 )
      return L"The state changed while waiting to process the sample.";
    if ( a1 > -2147220980 )
    {
      switch ( a1 )
      {
        case -2147220979:
          result = L"The buffer is not big enough.";
          break;
        case -2147220978:
          result = L"An invalid alignment was specified.";
          break;
        case -2147220977:
          result = L"Cannot change allocated memory while the filter is active.";
          break;
        case -2147220976:
          result = L"One or more buffers are still active.";
          break;
        case -2147220975:
          result = L"Cannot allocate a sample when the allocator is not active.";
          break;
        case -2147220974:
          result = L"Cannot allocate memory because no size has been set.";
          break;
        case -2147220973:
          result = L"Cannot lock for synchronization because no clock has been defined.";
          break;
        case -2147220972:
          result = L"Quality messages could not be sent because no quality sink has been defined.";
          break;
        case -2147220971:
          result = L"A required interface has not been implemented.";
          break;
        case -2147220970:
          result = L"An object or name was not found.";
          break;
        case -2147220969:
          result = L"No combination of intermediate filters could be found to make the connection.";
          break;
        case -2147220968:
          result = L"No combination of filters could be found to render the stream.";
          break;
        case -2147220967:
          result = L"Could not change formats dynamically.";
          break;
        case -2147220966:
          result = L"No color key has been set.";
          break;
        case -2147220965:
          result = L"Current pin connection is not using the IOverlay transport.";
          break;
        case -2147220964:
          result = L"Current pin connection is not using the IMemInputPin transport.";
          break;
        case -2147220963:
          result = L"Setting a color key would conflict with the palette already set.";
          break;
        case -2147220962:
          result = L"Setting a palette would conflict with the color key already set.";
          break;
        case -2147220961:
          result = L"No matching color key is available.";
          break;
        case -2147220960:
          result = L"No palette is available.";
          break;
        case -2147220959:
          result = L"Display does not use a palette.";
          break;
        case -2147220958:
          result = L"Too many colors for the current display settings.";
          break;
        default:
          return L"n/a";
      }
    }
    else
    {
      if ( a1 == -2147220980 )
        return L"No buffer space has been set";
      if ( a1 <= -2147220992 )
      {
        if ( a1 == -2147220992 )
          return L"Unable to IDirectInputJoyConfig_Acquire because the user does not have sufficient privileges to change "
                 L"the joystick configuration. & An invalid media type was specified";
        if ( a1 > -2147467259 )
        {
          switch ( a1 )
          {
            case -2147418113:
              return L"Catastrophic failure";
            case -2147221232:
              return L"This object does not support aggregation";
            case -2147221164:
              return L"Class not registered";
            case -2147221008:
              return L"CoInitialize has not been called.";
            case -2147221007:
              return L"CoInitialize has already been called.";
          }
        }
        else
        {
          switch ( a1 )
          {
            case -2147467259:
              return L"An undetermined error occurred";
            case -2147483638:
              return L"The data necessary to complete this operation is not yet available.";
            case -2147467263:
              return L"The function called is not supported at this time";
            case -2147467262:
              return L"The requested COM interface is not available";
            case -2147467261:
              return L"Invalid pointer";
            case -2147467260:
              return L"Operation aborted";
          }
        }
        return L"n/a";
      }
      switch ( a1 )
      {
        case -2147220991:
          result = L"The device is full. & An invalid media subtype was specified.";
          break;
        case -2147220990:
          result = L"Not all the requested information fit into the buffer. & This object can only be created as an aggregated object.";
          break;
        case -2147220989:
          result = L"The effect is not downloaded. & The enumerator has become invalid.";
          break;
        case -2147220988:
          result = L"The device cannot be reinitialized because there are still effects attached to it. & At least one of "
                   L"the pins involved in the operation is already connected.";
          break;
        case -2147220987:
          result = L"The operation cannot be performed unless the device is acquired in DISCL_EXCLUSIVE mode. & This opera"
                   L"tion cannot be performed because the filter is active.";
          break;
        case -2147220986:
          result = L"The effect could not be downloaded because essential information is missing.  For example, no axes ha"
                   L"ve been associated with the effect, or no type-specific information has been created. & One of the sp"
                   L"ecified pins supports no media types.";
          break;
        case -2147220985:
          result = L"Attempted to read buffered device data from a device that is not buffered. & There is no common media"
                   L" type between these pins.";
          break;
        case -2147220984:
          result = L"An attempt was made to modify parameters of an effect while it is playing.  Not all hardware devices "
                   L"support altering the parameters of an effect while it is playing. & Two pins of the same direction ca"
                   L"nnot be connected together.";
          break;
        case -2147220983:
          result = L"The operation could not be completed because the device is not plugged in. & The operation cannot be "
                   L"performed because the pins are not connected.";
          break;
        case -2147220982:
          result = L"SendDeviceData failed because more information was requested to be sent than can be sent to the devic"
                   L"e.  Some devices have restrictions on how much data can be sent to them.  (For example, there might b"
                   L"e a limit on the number of buttons that can be pressed at once.) & No sample buffer allocator is available.";
          break;
        case -2147220981:
          result = L"A mapper file function failed because reading or writing the user or IHV settings file failed. & A ru"
                   L"n-time error occurred.";
          break;
        default:
          return L"n/a";
      }
    }
  }
  return result;
}


} // namespace gpg

namespace gpg::gal
{
  namespace
  {
    void ReleaseSharedCount(boost::detail::sp_counted_base*& control) noexcept
    {
      if (control != nullptr) {
        control->release();
        control = nullptr;
      }
    }

    void PreserveCursorControlTransferSideEffects(boost::detail::sp_counted_base* const control) noexcept
    {
      if (control != nullptr) {
        control->add_ref_copy();
        control->release();
      }
    }

    /**
     * Address: 0x00940940 (FUN_00940940)
     *
     * What it does:
     * Re-runs `Class` constructor side effects for ABI adapter lanes that
     * ignore constructor return values.
     */
    [[maybe_unused]] void ResetClassVtableVoidAdapter(Class* const instance) noexcept
    {
      static_cast<void>(::new (instance) Class());
    }

    /**
     * Address: 0x0093F710 (FUN_0093F710)
     * Mangled: ??1EffectMacro@gal@gpg@@UAE@XZ
     *
     * What it does:
     * Applies legacy MSVC8 `_Tidy` semantics to both `EffectMacro` string lanes.
     */
    void DestroyEffectMacroBody(EffectMacro* const effectMacro) noexcept
    {
      effectMacro->valueText_.tidy(true, 0U);
      effectMacro->keyText_.tidy(true, 0U);
    }

    /**
     * Address: 0x00940470 (FUN_00940470)
     * Mangled: ??_DError@gal@gpg@@QAEXXZ
     *
     * What it does:
     * Applies legacy MSVC8 `_Tidy` semantics to both `Error` string lanes.
     */
    void DestroyErrorBody(Error* const error) noexcept
    {
      error->message_.tidy(true, 0U);
      error->runtimeMessage_.tidy(true, 0U);
    }

    /**
     * Address: 0x00437850 (FUN_00437850)
     *
     * What it does:
     * Applies legacy `_Tidy(true, 0)` teardown to one contiguous
     * `HeadSampleOption` label-string range.
     */
    void DestroyHeadSampleOptionRange(HeadSampleOption* begin, HeadSampleOption* const end) noexcept
    {
      for (; begin != end; ++begin) {
        begin->label.tidy(true, 0U);
      }
    }

    template <class T>
    void ReleaseVectorStorage(msvc8::vector<T>& vector) noexcept
    {
      msvc8::vector_runtime_view<T>& runtime = msvc8::AsVectorRuntimeView(vector);
      if (runtime.begin != nullptr) {
        ::operator delete(static_cast<void*>(runtime.begin));
      }

      runtime.begin = nullptr;
      runtime.end = nullptr;
      runtime.capacityEnd = nullptr;
    }
  } // namespace

  /**
   * Address: 0x0093F090 (FUN_0093F090, gpg::gal::DrawIndexedContext::DrawIndexedContext)
   * Mangled: ??0DrawIndexedContext@gal@gpg@@QAE@XZ
   *
   * What it does:
   * Initializes indexed-draw payload lanes to their zero/default values.
   */
  DrawIndexedContext::DrawIndexedContext()
      : topologyToken_(0),
        minVertexIndex_(0),
        vertexCount_(0),
        primitiveCountInput_(0),
        startIndex_(0),
        baseVertexIndex_(0)
  {
  }

  /**
   * Address: 0x0093F0B0 (FUN_0093F0B0, gpg::gal::DrawIndexedContext::DrawIndexedContext)
   *
   * What it does:
   * Initializes indexed-draw payload lanes for topology, vertex count,
   * primitive count, start index, and base vertex index.
   */
  DrawIndexedContext::DrawIndexedContext(
    const int topology,
    const int numVertices,
    const int primCount,
    const int startIndex,
    const int baseVertIndex
  )
      : topologyToken_(static_cast<std::uint32_t>(topology)),
        minVertexIndex_(0),
        vertexCount_(static_cast<std::uint32_t>(numVertices)),
        primitiveCountInput_(static_cast<std::uint32_t>(primCount)),
        startIndex_(static_cast<std::uint32_t>(startIndex)),
        baseVertexIndex_(baseVertIndex)
  {
  }

  /**
   * Address: 0x0093F0F0 (FUN_0093F0F0, gpg::gal::DrawIndexedContext::DrawIndexedContext)
   * Mangled: ??0DrawIndexedContext@gal@gpg@@QAE@@Z
   *
   * What it does:
   * Initializes indexed-draw payload lanes, including explicit minimum
   * vertex index and base-vertex bias.
   */
  DrawIndexedContext::DrawIndexedContext(
    const std::uint32_t topologyToken,
    const std::uint32_t minVertexIndex,
    const std::uint32_t vertexCount,
    const std::uint32_t primitiveCountInput,
    const std::uint32_t startIndex,
    const std::int32_t baseVertexIndex
  )
      : topologyToken_(topologyToken),
        minVertexIndex_(minVertexIndex),
        vertexCount_(vertexCount),
        primitiveCountInput_(primitiveCountInput),
        startIndex_(startIndex),
        baseVertexIndex_(baseVertexIndex)
  {
  }

  /**
   * Address: 0x0093F130 (FUN_0093F130, gpg::gal::DrawIndexedContext::~DrawIndexedContext)
   * Address: 0x0093F160 (FUN_0093F160)
   *
   * What it does:
   * Restores DrawIndexedContext vftable ownership and services deleting
   * destructor thunk teardown.
   */
  DrawIndexedContext::~DrawIndexedContext() = default;

  /**
   * Address: 0x0093EEA0 (FUN_0093EEA0, __imp_??0CursorContext@gal@gpg@@QAE@XZ)
   *
   * What it does:
   * Initializes cursor hotspot/pixel-source/control lanes to zero/null.
   */
  CursorContext::CursorContext()
    : hotspotX_(0)
    , hotspotY_(0)
    , pixelSource_(nullptr)
    , cursorControl_(nullptr)
  {
  }

  /**
   * Address: 0x0093EF20 (FUN_0093EF20)
   *
   * int,int,CursorPixelSourceRuntime *,boost::detail::sp_counted_base *
   *
   * What it does:
   * Initializes cursor hotspot/pixel-source/control lanes from caller payload
   * and preserves legacy shared-count transfer side effects for cursor control.
   */
  CursorContext::CursorContext(
    const std::int32_t hotspotX,
    const std::int32_t hotspotY,
    CursorPixelSourceRuntime* const pixelSource,
    boost::detail::sp_counted_base* const cursorControl
  )
    : hotspotX_(hotspotX)
    , hotspotY_(hotspotY)
    , pixelSource_(pixelSource)
    , cursorControl_(cursorControl)
  {
    PreserveCursorControlTransferSideEffects(cursorControl_);
  }

  /**
   * Address: 0x0093EE60 (FUN_0093EE60, __imp_??1CursorContext@gal@gpg@@UAE@XZ)
   * Scalar-deleting wrapper: 0x0093EEC0 (FUN_0093EEC0)
   *
   * What it does:
   * Releases the retained cursor-control shared-count block before object teardown.
   */
  CursorContext::~CursorContext()
  {
    ReleaseSharedCount(cursorControl_);
  }

  /**
   * Address: 0x00940930 (FUN_00940930)
   *
   * What it does:
   * Initializes one abstract `gal::Class` base lane by installing the class
   * vtable.
   */
  Class::Class() = default;

  /**
   * Address: 0x00940950 (FUN_00940950)
   *
   * What it does:
   * Scalar-deleting destructor thunk owner for gal::Class instances.
   */
  Class::~Class() = default;

  /**
   * Address: 0x008FA9A0 (FUN_008FA9A0)
   *
   * What it does:
   * Copy-constructs effect-macro text lanes through legacy string assign
   * semantics for key/value payloads.
   */
  EffectMacro::EffectMacro(const EffectMacro& other)
    : keyText_()
    , valueText_()
  {
    keyText_.assign(other.keyText_, 0U, msvc8::string::npos);
    valueText_.assign(other.valueText_, 0U, msvc8::string::npos);
  }

  /**
   * Address: 0x0093F8B0 (FUN_0093F8B0)
   *
   * What it does:
   * Constructs one effect-macro entry from raw C-string key/value payloads.
   */
  EffectMacro::EffectMacro(const char* const keyText, const char* const valueText)
    : keyText_()
    , valueText_()
  {
    keyText_.assign(keyText, std::strlen(keyText));
    valueText_.assign(valueText, std::strlen(valueText));
  }

  /**
   * Address: 0x008FAA20 (FUN_008FAA20)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates to `FUN_0093F710` body semantics.
   */
  EffectMacro::~EffectMacro()
  {
    DestroyEffectMacroBody(this);
  }

  /**
   * Address: 0x009404D0 (FUN_009404D0)
   * Mangled: ??0Error@gal@gpg@@QAE@@Z
   *
   * What it does:
   * Initializes file/line/message payload lanes for gal error exceptions.
   */
  Error::Error(const msvc8::string& file, const int line, const msvc8::string& message)
    : std::exception()
  {
    runtimeMessage_.assign(file, 0U, msvc8::string::npos);
    line_ = line;
    message_.assign(message, 0U, msvc8::string::npos);
  }

  /**
   * Address: 0x008A7B10 (FUN_008A7B10)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates to `FUN_00940470` body semantics.
   */
  Error::~Error()
  {
    DestroyErrorBody(this);
  }

  /**
   * Address: 0x00940460 (FUN_00940460)
   *
   * What it does:
   * Returns the raw message data pointer (SSO buffer or heap pointer).
   */
  const char* Error::what() const noexcept
  {
    return message_.raw_data_unsafe();
  }

  /**
   * Address: 0x00940440 (FUN_00940440)
   *
   * What it does:
   * Returns the stored source line captured by the constructor payload.
   */
  int Error::GetRuntimeLine() const noexcept
  {
    return line_;
  }

  /**
   * Address: 0x00940450 (FUN_00940450)
   *
   * What it does:
   * Returns the throw-site runtime text pointer from `runtimeMessage_`.
   */
  const char* Error::GetRuntimeMessage() const noexcept
  {
    return runtimeMessage_.raw_data_unsafe();
  }

  /**
   * Address: 0x008E6D80 (FUN_008E6D80, gpg::gal::Head::Head)
   *
   * What it does:
   * Initializes one GAL head descriptor and zeroes scalar/runtime vector
   * lanes.
   */
  Head::Head() = default;

  /**
   * Address: 0x004368B0 (FUN_004368B0)
   *
   * What it does:
   * Copy-constructs one GAL head descriptor by default-initializing this lane
   * and applying `operator=` to copy owned payloads.
   */
  Head::Head(const Head& other)
    : Head()
  {
    *this = other;
  }

  /**
   * Address: 0x008D7310 (FUN_008D7310)
   *
   * What it does:
   * Copies one GAL head descriptor lane in-place, including owned text and
   * nested vector payloads, without altering the vftable.
   */
  Head& Head::operator=(const Head& other)
  {
    mHandle = other.mHandle;
    mWindow = other.mWindow;
    mWindowed = other.mWindowed;
    mWidth = other.mWidth;
    mHeight = other.mHeight;
    framesPerSecond = other.framesPerSecond;
    antialiasingHigh = other.antialiasingHigh;
    antialiasingLow = other.antialiasingLow;
    name.assign(other.name, 0U, msvc8::string::npos);
    mStrs = other.mStrs;
    adapterModes = other.adapterModes;
    validFormats2 = other.validFormats2;
    validFormats1 = other.validFormats1;
    return *this;
  }

  /**
   * Address: 0x008E6EA0 (FUN_008E6EA0, gpg::gal::Head::~Head)
   * Address: 0x00436990 (FUN_00436990)
   *
   * What it does:
   * Tears down all retained `Head` vector/string payload lanes in-place;
   * `0x00436990` is the scalar-deleting thunk that dispatches here and
   * conditionally frees `this`.
   */
  Head::~Head()
  {
    ReleaseVectorStorage(validFormats1);
    ReleaseVectorStorage(validFormats2);
    ReleaseVectorStorage(adapterModes);

    msvc8::vector_runtime_view<HeadSampleOption>& sampleOptionsRuntime = msvc8::AsVectorRuntimeView(mStrs);
    if (sampleOptionsRuntime.begin != nullptr) {
      DestroyHeadSampleOptionRange(sampleOptionsRuntime.begin, sampleOptionsRuntime.end);
      ::operator delete(static_cast<void*>(sampleOptionsRuntime.begin));
    }

    sampleOptionsRuntime.begin = nullptr;
    sampleOptionsRuntime.end = nullptr;
    sampleOptionsRuntime.capacityEnd = nullptr;

    name.tidy(true, 0U);
  }
} // namespace gpg::gal
